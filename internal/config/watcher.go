package config

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// Watcher watches the global config file and a proxies directory for changes
// and emits Change events so the proxy manager can perform scoped live reloads.
//
// A single Watcher covers both files to keep filesystem handle churn minimal.
// Debounce is applied per-path so rapid editor "atomic rename" save bursts
// collapse into a single reload notification — without this an editor such as
// vim or `sed -i` produces a DELETE+CREATE storm that triggers spurious reloads.
type Watcher struct {
	logger    *zap.Logger
	fw        *fsnotify.Watcher
	global    string
	proxyDir  string

	// pending holds the last event time per path keyed by the clean abs path.
	pending   map[string]time.Time
	pendingMu sync.Mutex
	debounce  time.Duration

	out   chan Change
	stop  chan struct{}
	done  chan struct{}
}

// Change is a single debounced reload notification.
type Change struct {
	Kind     ChangeKind
	Path     string // absolute, cleaned path of the affected file
	IsGlobal bool   // true if the change affects the global config
}

// ChangeKind enumerates the filesystem events the watcher reports.
type ChangeKind int

const (
	// ChangeUpdate covers writes, creates, chmod-then-write, and renames into
	// place. We deliberately merge all of these because at reload time the proxy
	// manager re-reads the file fresh — distinguishing create vs. modify adds no
	// value here.
	ChangeUpdate ChangeKind = iota
	// ChangeRemove covers deletions of per-proxy files. The manager uses this
	// to stop a removed proxy's instance.
	ChangeRemove
)

// Close releases the underlying fsnotify watcher and stops background goroutines.
// Safe to call concurrently with Next. After Close, Next's channel closes.
func (w *Watcher) Close() error {
	close(w.stop)
	var err error
	if w.fw != nil {
		err = w.fw.Close()
	}
	return err
}

// Events returns the channel that receives Change notifications. The channel
// is closed when Close is called.
func (w *Watcher) Events() <-chan Change { return w.out }

// NewWatcher constructs a Watcher over the supplied global config path and proxy
// directory. Both paths must already exist (the proxies directory may be empty).
//
// The supplied logger must be non-nil. Errors during initial watch registration
// are returned immediately — once the watcher is running, all filesystem errors
// are funneled through the events interface and the logger instead of panic.
func NewWatcher(globalPath, proxyDir string, logger *zap.Logger) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		logger:   logger,
		fw:       fw,
		global:   filepath.Clean(globalPath),
		proxyDir: filepath.Clean(proxyDir),
		pending:  make(map[string]time.Time),
		debounce: 200 * time.Millisecond,
		out:      make(chan Change, 16),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}

	absGlobal, err := filepath.Abs(globalPath)
	if err != nil {
		_ = fw.Close()
		return nil, err
	}
	if err := fw.Add(absGlobal); err != nil {
		_ = fw.Close()
		return nil, err
	}
	w.global = absGlobal

	absDir, err := filepath.Abs(proxyDir)
	if err != nil {
		_ = fw.Close()
		return nil, err
	}
	if err := fw.Add(absDir); err != nil {
		_ = fw.Close()
		return nil, err
	}
	w.proxyDir = absDir

	go w.run()
	return w, nil
}

// run owns the read loop. It exits when either stop is closed or the underlying
// watcher's error channel terminates — both paths unblock through done.
func (w *Watcher) run() {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case ev, ok := <-w.fw.Events:
			if !ok {
				return
			}
			w.handle(ev)
		case err, ok := <-w.fw.Errors:
			if !ok {
				return
			}
			if err != nil && w.logger != nil {
				w.logger.Warn("config watcher filesystem error",
					zap.String("global", w.global),
					zap.String("dir", w.proxyDir),
					zap.Error(err))
			}
		}
	}
}

// handle maps a raw fsnotify event to a ChangeKind and applies debouncing.
// Writes/creates are coalesced into ChangeUpdate with a 200ms quiet window.
// Removes pass straight through to ChangeRemove (no debounce) so a deleted
// proxy file is reaped without delay.
func (w *Watcher) handle(ev fsnotify.Event) {
	path := filepath.Clean(ev.Name)
	isGlobal := path == w.global
	isProxy := !isGlobal && strings.HasPrefix(path, w.proxyDir+string(filepath.Separator))
	if !isGlobal && !isProxy {
		return
	}
	if isProxy {
		low := strings.ToLower(filepath.Ext(path))
		if low != ".yaml" && low != ".yml" {
			return
		}
	}

	kind := ChangeUpdate
	if ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
		kind = ChangeRemove
	}

	// Remove events are transient - no debounce, push straight through.
	if kind == ChangeRemove {
		w.emit(Change{Kind: kind, Path: path, IsGlobal: isGlobal})
		return
	}

	seed := time.Now()
	w.pendingMu.Lock()
	w.pending[path] = seed
	w.pendingMu.Unlock()

	go w.scheduleEmit(path, isGlobal, seed)
}

// scheduleEmit waits for the debounce window to elapse without further events
// on the same path, then emits the Change. If a newer event lands before the
// timer fires, pending[path] will no longer equal the seed timestamp recorded
// when this goroutine was scheduled — the newer scheduleEmit goroutine owns
// the emit, and this one exits silently.
func (w *Watcher) scheduleEmit(path string, isGlobal bool, seed time.Time) {
	select {
	case <-w.stop:
		return
	case <-time.After(w.debounce):
	}
	w.pendingMu.Lock()
	if cur := w.pending[path]; !cur.Equal(seed) {
		w.pendingMu.Unlock()
		return
	}
	delete(w.pending, path)
	w.pendingMu.Unlock()
	w.emit(Change{Kind: ChangeUpdate, Path: path, IsGlobal: isGlobal})
}

// emit safely ships a Change onto the buffered events channel. Blocks up to
// the poll guard to avoid slow consumers wedging the watcher permanently.
func (w *Watcher) emit(c Change) {
	select {
	case w.out <- c:
	case <-w.stop:
	case <-time.After(5 * time.Second):
		if w.logger != nil {
			w.logger.Warn("config watcher: events channel full, dropping event",
				zap.String("path", c.Path))
		}
	}
}

// Wait blocks until the watcher has fully shut down its internal goroutine.
// Useful in tests to assert deterministic teardown.
func (w *Watcher) Wait(ctx context.Context) error {
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}