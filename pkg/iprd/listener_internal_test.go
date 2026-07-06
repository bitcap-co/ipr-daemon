package iprd

import (
	"context"
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
