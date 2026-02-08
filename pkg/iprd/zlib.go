package iprd

import (
	"bytes"
	"compress/zlib"
	"io"
)

const (
	zlibNoCompression byte = 0x01
	zlibFast          byte = 0x5e
	zlibDefault       byte = 0x9c
	zlibBest          byte = 0xda
)

// static offsets
const (
	smHeaderOffset int64 = 8
)

func matchHeaderAtOffset(b *bytes.Reader, offset int64) bool {
	magicBuf := make([]byte, 2)
	_, err := b.ReadAt(magicBuf, offset)
	if err != nil {
		return false
	}
	if bytes.Equal(magicBuf, []byte{0x78, zlibDefault}) {
		return true
	}
	return false
}

func zlibReaderAtOffset(b *bytes.Reader, offset int64) (io.ReadCloser, error) {
	// reset reader
	if _, err := b.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := b.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	return r, nil
}
