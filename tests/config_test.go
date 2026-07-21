package iprd_test

import (
	"testing"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func TestValidateForwardBind(t *testing.T) {
	tests := []struct {
		name    string
		bind    string
		wantErr bool
	}{
		{"empty binds all interfaces", "", false},
		{"valid IPv4", "192.168.1.10", false},
		{"valid loopback", "127.0.0.1", false},
		{"valid IPv6", "::1", false},
		{"garbage string", "not-an-ip", true},
		{"trailing junk", "192.168.1.10x", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := iprd.DefaultIPRDConfig()
			cfg.ForwardBind = tt.bind
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() with bind %q: got err=%v, wantErr=%v", tt.bind, err, tt.wantErr)
			}
		})
	}
}

func TestMDNSRoundTrip(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`mdns = true`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	if !cfg.MDNS {
		t.Fatal("got MDNS false, want true")
	}
}

func TestRotateCaptureFilesRoundTrip(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`rotate_capture_files = true`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	if !cfg.RotateCaptureFiles {
		t.Fatal("got RotateCaptureFiles false, want true")
	}
}

func TestForwardBindRoundTrip(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`forward_bind = "127.0.0.1"`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	if cfg.ForwardBind != "127.0.0.1" {
		t.Fatalf("got ForwardBind %q, want %q", cfg.ForwardBind, "127.0.0.1")
	}
}
