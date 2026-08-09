package iprd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gopacket/gopacket/pcapgo"
)

const (
	captureSnapLen     uint32 = 1600
	maxCaptureFileSize int64  = 4 * 1024 * 1024 // max capture file size of 4 MiB
	maxCaptureFiles           = 4
)

type countingWriter struct {
	writer io.Writer
	bytes  int64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.bytes += int64(n)
	return n, err
}

type captureInterfaceKey struct {
	name     string
	linkType uint16
}

// CaptureWriter writes interface-tagged packets to a bounded PCAP-NG capture.
// It is owned by ListenerManager and must be called serially.
type CaptureWriter struct {
	path       string
	rotate     bool
	log        Logger
	file       *os.File
	counter    *countingWriter
	writer     *pcapgo.NgWriter
	interfaces map[captureInterfaceKey]int
}

// NewCaptureWriter returns a PCAP-NG writer. An empty path disables capture.
func NewCaptureWriter(path string, rotate bool, logger Logger) *CaptureWriter {
	if logger == nil {
		logger = NewLogger()
	}
	if path != "" {
		path = normalizeCapturePath(path)
	}
	return &CaptureWriter{
		path:   path,
		rotate: rotate,
		log:    logger,
	}
}

// Path returns the normalized capture path, or an empty string when disabled.
func (w *CaptureWriter) Path() string {
	return w.path
}

// Open validates and creates the configured capture path. The PCAP-NG section
// is initialized lazily when the first packet supplies interface metadata.
func (w *CaptureWriter) Open() error {
	if w.path == "" || w.file != nil {
		return nil
	}
	if err := w.createFile(); err != nil {
		return err
	}
	w.log.Info(fmt.Sprintf("capturing packets to -> %s", w.path))
	return nil
}

// Write writes and flushes a captured packet, then applies the configured size
// limit. Flushing keeps byte accounting accurate and capture data durable.
func (w *CaptureWriter) Write(packet CapturedPacket) error {
	if w.path == "" {
		return nil
	}
	if w.file == nil {
		return fmt.Errorf("capture writer is not open")
	}

	interfaceID, err := w.ensureInterface(packet)
	if err != nil {
		return err
	}
	ci := packet.CaptureInfo
	ci.InterfaceIndex = interfaceID
	if err := w.writer.WritePacket(ci, packet.Data); err != nil {
		return fmt.Errorf("write packet: %w", err)
	}
	if err := w.writer.Flush(); err != nil {
		return fmt.Errorf("flush packet: %w", err)
	}
	if w.counter.bytes >= maxCaptureFileSize {
		return w.rollCaptureFile()
	}
	return nil
}

// Close flushes and closes the active capture file.
func (w *CaptureWriter) Close() error {
	if w.file == nil {
		return nil
	}
	var flushErr error
	if w.writer != nil {
		flushErr = w.writer.Flush()
	}
	closeErr := w.file.Close()
	w.file = nil
	w.counter = nil
	w.writer = nil
	w.interfaces = nil
	return errors.Join(flushErr, closeErr)
}

func (w *CaptureWriter) ensureInterface(packet CapturedPacket) (int, error) {
	name := packet.Interface.Name
	if name == "" {
		name = packet.Interface.FriendlyName
	}
	if name == "" {
		name = fmt.Sprintf("interface-%d", packet.Interface.Index)
	}
	key := captureInterfaceKey{name: name, linkType: uint16(packet.LinkType)}
	if id, ok := w.interfaces[key]; ok {
		return id, nil
	}

	intf := pcapgo.DefaultNgInterface
	intf.Name = name
	intf.Description = packet.Interface.Description
	intf.LinkType = packet.LinkType
	intf.SnapLength = captureSnapLen
	if w.writer == nil {
		writer, err := pcapgo.NewNgWriterInterface(w.counter, intf, pcapgo.DefaultNgWriterOptions)
		if err != nil {
			return 0, fmt.Errorf("create pcapng writer: %w", err)
		}
		w.writer = writer
		w.interfaces[key] = 0
		return 0, nil
	}
	id, err := w.writer.AddInterface(intf)
	if err != nil {
		return 0, fmt.Errorf("add capture interface %q: %w", name, err)
	}
	w.interfaces[key] = id
	return id, nil
}

func (w *CaptureWriter) createFile() error {
	file, err := os.Create(w.path)
	if err != nil {
		return fmt.Errorf("failed to open capture file: %w", err)
	}
	w.file = file
	w.counter = &countingWriter{writer: file}
	w.writer = nil
	w.interfaces = make(map[captureInterfaceKey]int)
	return nil
}

func (w *CaptureWriter) rollCaptureFile() error {
	if err := w.Close(); err != nil {
		return fmt.Errorf("close active capture: %w", err)
	}
	var rotateErr error
	if w.rotate {
		rotateErr = rotateCaptureFiles(w.path, maxCaptureFiles)
	}
	openErr := w.createFile()
	if rotateErr != nil || openErr != nil {
		return errors.Join(rotateErr, openErr)
	}
	if w.rotate {
		w.log.Info(fmt.Sprintf("capture file reached %d bytes, rotated (keeping %d files)", maxCaptureFileSize, maxCaptureFiles))
	} else {
		w.log.Info(fmt.Sprintf("capture file reached %d bytes, flushed", maxCaptureFileSize))
	}
	return nil
}

func normalizeCapturePath(path string) string {
	ext := filepath.Ext(path)
	if strings.EqualFold(ext, ".pcapng") {
		return path
	}
	if strings.TrimSuffix(path, ext) == "" {
		return path + ".pcapng"
	}
	return strings.TrimSuffix(path, ext) + ".pcapng"
}

func rotatedCapturePath(path string, index int) string {
	ext := filepath.Ext(path)
	return fmt.Sprintf("%s.%d%s", strings.TrimSuffix(path, ext), index, ext)
}

func rotateCaptureFiles(path string, maxFiles int) error {
	oldest := rotatedCapturePath(path, maxFiles-1)
	if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove oldest capture %q: %w", oldest, err)
	}
	for index := maxFiles - 1; index >= 1; index-- {
		source := path
		if index > 1 {
			source = rotatedCapturePath(path, index-1)
		}
		destination := rotatedCapturePath(path, index)
		if err := os.Rename(source, destination); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("rotate capture %q to %q: %w", source, destination, err)
		}
	}
	return nil
}
