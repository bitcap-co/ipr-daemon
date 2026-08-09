package iprd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket/pcapgo"
)

func TestNormalizeCapturePath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"capture", "capture.pcapng"},
		{"capture.log", "capture.pcapng"},
		{"capture.pcap", "capture.pcapng"},
		{"capture.pcapng", "capture.pcapng"},
		{".capture", ".capture.pcapng"},
		{"captures.v1/capture.pcapng", "captures.v1/capture.pcapng"},
	}
	for _, tt := range tests {
		if got := normalizeCapturePath(tt.path); got != tt.want {
			t.Errorf("normalizeCapturePath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestRotateCaptureFilesKeepsFourNewest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcapng")

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

func TestCaptureWriterWritesMultipleInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	writer := NewCaptureWriter(path, false, NewLogger())
	if err := writer.Open(); err != nil {
		t.Fatal(err)
	}

	first := capturedIPReport(t, "aa:bb:cc:dd:ee:11", 14235, 3)
	first.Interface.Name = "eth0"
	second := capturedIPReport(t, "aa:bb:cc:dd:ee:12", 14235, 7)
	second.Interface.Name = "eth1"
	if err := writer.Write(first); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(second); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(writer.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewNgReader(file, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		t.Fatal(err)
	}
	for index, wantName := range []string{"eth0", "eth1"} {
		_, ci, err := reader.ReadPacketData()
		if err != nil {
			t.Fatalf("read packet %d: %v", index, err)
		}
		if ci.InterfaceIndex != index {
			t.Fatalf("packet %d interface ID = %d, want %d", index, ci.InterfaceIndex, index)
		}
		intf, err := reader.Interface(ci.InterfaceIndex)
		if err != nil {
			t.Fatal(err)
		}
		if intf.Name != wantName {
			t.Fatalf("packet %d interface name = %q, want %q", index, intf.Name, wantName)
		}
	}
}

func TestCaptureWriterValidatesPathOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "capture.pcapng")
	writer := NewCaptureWriter(path, false, NewLogger())
	if err := writer.Open(); err == nil {
		t.Fatal("Open() returned nil error for a missing parent directory")
	}
}
