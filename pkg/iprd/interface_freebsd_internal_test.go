//go:build freebsd

package iprd

import (
	"testing"
	"unsafe"
)

func TestFreeBSDVlanReqABILayout(t *testing.T) {
	var req freeBSDVlanReq

	if got := unsafe.Sizeof(req); got != 20 {
		t.Errorf("freeBSDVlanReq size = %d, want 20", got)
	}
	if got := unsafe.Offsetof(req.Tag); got != 16 {
		t.Errorf("freeBSDVlanReq.Tag offset = %d, want 16", got)
	}
	if got := unsafe.Offsetof(req.Proto); got != 18 {
		t.Errorf("freeBSDVlanReq.Proto offset = %d, want 18", got)
	}
}

func TestFreeBSDIfReqABILayout(t *testing.T) {
	var req freeBSDIfReq

	if got := unsafe.Sizeof(req); got != 32 {
		t.Errorf("freeBSDIfReq size = %d, want 32", got)
	}
	if got := unsafe.Offsetof(req.Data); got != 16 {
		t.Errorf("freeBSDIfReq.Data offset = %d, want 16", got)
	}
}
