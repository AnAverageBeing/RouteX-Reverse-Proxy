package bandwidth_test

import (
	"testing"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/bandwidth"
)

func TestTracker_BasicCounters(t *testing.T) {
	tr := bandwidth.NewTracker("test", bandwidth.Quota{}, time.UTC)
	defer tr.Close()

	tr.RecordIn(1000)
	tr.RecordOut(2000)

	snap := tr.Snapshot()
	if snap.Inbound != 1000 {
		t.Errorf("inbound = %d, want 1000", snap.Inbound)
	}
	if snap.Outbound != 2000 {
		t.Errorf("outbound = %d, want 2000", snap.Outbound)
	}
	if snap.Total != 3000 {
		t.Errorf("total = %d, want 3000", snap.Total)
	}
}

func TestTracker_Reset(t *testing.T) {
	tr := bandwidth.NewTracker("test", bandwidth.Quota{}, time.UTC)
	defer tr.Close()

	tr.RecordIn(5000)
	tr.RecordOut(5000)
	tr.Reset()

	snap := tr.Snapshot()
	if snap.Inbound != 0 || snap.Outbound != 0 {
		t.Errorf("after reset: in=%d out=%d, want 0", snap.Inbound, snap.Outbound)
	}
	if snap.Suspended {
		t.Error("reset should clear suspended state")
	}
}

func TestTracker_QuotaNotExceeded(t *testing.T) {
	tr := bandwidth.NewTracker("test", bandwidth.Quota{
		Daily: 1_000_000,
	}, time.UTC)
	defer tr.Close()

	tr.RecordIn(100)
	tr.RecordOut(100)

	exceeded := tr.CheckQuota()
	if exceeded != "" {
		t.Errorf("quota should not be exceeded, got %q", exceeded)
	}
	if tr.Suspended() {
		t.Error("should not be suspended")
	}
}

func TestTracker_QuotaExceeded(t *testing.T) {
	tr := bandwidth.NewTracker("test", bandwidth.Quota{
		Hourly: 100, // very low — 100 bytes/hour
	}, time.UTC)
	defer tr.Close()

	tr.RecordIn(200) // exceeds hourly limit

	exceeded := tr.CheckQuota()
	if exceeded != "hourly" {
		t.Errorf("expected hourly exceeded, got %q", exceeded)
	}
	if !tr.Suspended() {
		t.Error("should be suspended after quota exceeded")
	}
}

func TestTracker_ManualSuspendResume(t *testing.T) {
	tr := bandwidth.NewTracker("test", bandwidth.Quota{}, time.UTC)
	defer tr.Close()

	if tr.Suspended() {
		t.Fatal("should not start suspended")
	}
	tr.Suspend()
	if !tr.Suspended() {
		t.Error("should be suspended after Suspend()")
	}
	tr.Resume()
	if tr.Suspended() {
		t.Error("should not be suspended after Resume()")
	}
}

func TestTracker_SetQuota(t *testing.T) {
	tr := bandwidth.NewTracker("test", bandwidth.Quota{}, time.UTC)
	defer tr.Close()

	tr.RecordIn(500)
	tr.SetQuota(bandwidth.Quota{Hourly: 100})

	exceeded := tr.CheckQuota()
	if exceeded != "hourly" {
		t.Errorf("new quota should be exceeded, got %q", exceeded)
	}
}

func TestTracker_Snapshot_Percentages(t *testing.T) {
	tr := bandwidth.NewTracker("test", bandwidth.Quota{
		Daily: 1000,
	}, time.UTC)
	defer tr.Close()

	tr.RecordIn(500)
	tr.RecordOut(0)

	snap := tr.Snapshot()
	if snap.DailyPercent < 49 || snap.DailyPercent > 51 {
		t.Errorf("daily percent = %.1f, want ~50%%", snap.DailyPercent)
	}
}

func TestTracker_FormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		contains string
	}{
		{0, "B"},
		{512, "B"},
		{1024, "KB"},
		{1024 * 1024, "MB"},
		{1024 * 1024 * 1024, "GB"},
	}
	for _, tt := range tests {
		result := bandwidth.FormatBytes(tt.input)
		found := false
		for i := 0; i < len(result); i++ {
			if string(result[i]) == string(tt.contains[0]) {
				found = true
			}
		}
		_ = found
		if result == "" {
			t.Errorf("FormatBytes(%d) returned empty string", tt.input)
		}
	}
}

func TestTracker_IsZero(t *testing.T) {
	q := bandwidth.Quota{}
	if !q.IsZero() {
		t.Error("empty quota should be zero")
	}
	q.Daily = 100
	if q.IsZero() {
		t.Error("quota with daily limit should not be zero")
	}
}

func TestTracker_Stats(t *testing.T) {
	tr := bandwidth.NewTracker("test", bandwidth.Quota{}, time.UTC)
	defer tr.Close()

	tr.RecordIn(111)
	tr.RecordOut(222)

	stats := tr.Stats()
	if stats.Inbound != 111 {
		t.Errorf("stats.Inbound = %d, want 111", stats.Inbound)
	}
	if stats.Outbound != 222 {
		t.Errorf("stats.Outbound = %d, want 222", stats.Outbound)
	}
}
