package iprd_test

import (
	"reflect"
	"testing"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func TestFlagSliceSupportsChainingAndCommaSeparatedValues(t *testing.T) {
	var values iprd.FlagSlice
	for _, value := range []string{"eth0", "eth1, wlan0", "  4  ", ""} {
		if err := values.Set(value); err != nil {
			t.Fatalf("Set(%q): %v", value, err)
		}
	}

	want := iprd.FlagSlice{"eth0", "eth1", "wlan0", "4"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("got %v, want %v", values, want)
	}
	if got := values.String(); got != "eth0,eth1,wlan0,4" {
		t.Fatalf("String() = %q, want %q", got, "eth0,eth1,wlan0,4")
	}
}

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
