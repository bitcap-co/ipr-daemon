package iprd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNextBackoff(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want time.Duration
	}{
		{reconnectMinBackoff, 2 * time.Second},
		{2 * time.Second, 4 * time.Second},
		{16 * time.Second, reconnectMaxBackoff},    // 32s clamps to 30s
		{reconnectMaxBackoff, reconnectMaxBackoff}, // stays at cap
	}
	for _, tt := range tests {
		if got := nextBackoff(tt.in); got != tt.want {
			t.Fatalf("nextBackoff(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestSleepCtxCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, time.Hour) {
		t.Fatal("sleepCtx returned true for a cancelled context, want false")
	}
}

func TestSleepCtxElapsed(t *testing.T) {
	if !sleepCtx(context.Background(), time.Millisecond) {
		t.Fatal("sleepCtx returned false after the timer elapsed, want true")
	}
}

func TestNormalizeCapturePath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"capture", "capture.pcap"},
		{"capture.log", "capture.pcap"},
		{"capture.pcap", "capture.pcap"},
		{".capture", ".capture.pcap"},
		{"captures.v1/capture.pcap", "captures.v1/capture.pcap"},
	}
	for _, tt := range tests {
		if got := normalizeCapturePath(tt.path); got != tt.want {
			t.Errorf("normalizeCapturePath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestRotateCaptureFilesKeepsFourNewest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")

	for generation := 1; generation <= 6; generation++ {
		if err := os.WriteFile(path, []byte(fmt.Sprintf("capture-%d", generation)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := rotateCaptureFiles(path, maxCaptureFiles); err != nil {
			t.Fatalf("rotation %d failed: %v", generation, err)
		}
	}

	for index, generation := range []int{6, 5, 4} {
		archive := rotatedCapturePath(path, index+1)
		got, err := os.ReadFile(archive)
		if err != nil {
			t.Fatalf("read %q: %v", archive, err)
		}
		want := fmt.Sprintf("capture-%d", generation)
		if string(got) != want {
			t.Errorf("%q contains %q, want %q", archive, got, want)
		}
	}
	if _, err := os.Stat(rotatedCapturePath(path, maxCaptureFiles)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected fifth capture file: %v", err)
	}
}
