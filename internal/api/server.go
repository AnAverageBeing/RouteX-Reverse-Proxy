package api

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
)

type Server struct {
	srv    *http.Server
	logger *zap.Logger
}

type TLSConfig struct {
	Enabled bool
	Cert    string
	Key     string
}

func NewServer(bind string, handler http.Handler, tlsCfg *TLSConfig, logger *zap.Logger) *Server {
	srv := &http.Server{
		Addr:         bind,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	server := &Server{srv: srv, logger: logger}
	if tlsCfg != nil && tlsCfg.Enabled {
		cert, err := tls.LoadX509KeyPair(tlsCfg.Cert, tlsCfg.Key)
		if err != nil {
			logger.Fatal("failed to load TLS cert", zap.Error(err))
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}
	return server
}

func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	s.logger.Info("API server listening", zap.String("addr", s.srv.Addr))
	errCh := make(chan error, 1)
	go func() {
		if s.srv.TLSConfig != nil {
			errCh <- s.srv.ServeTLS(ln, "", "")
		} else {
			errCh <- s.srv.Serve(ln)
		}
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}
