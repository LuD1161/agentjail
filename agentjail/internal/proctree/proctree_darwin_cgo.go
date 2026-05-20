//go:build darwin && cgo

package proctree

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// parentOf reads the BSD-info block for pid via libproc.proc_pidinfo and
// returns pbi_ppid. This is the documented Apple way to walk the process
// tree without spawning a child — it's a single syscall (proc_info),
// constant-time, sub-microsecond on Apple Silicon.
//
// The pure-Go shell-out fallback lives in proctree_darwin.go and is
// selected when cgo is disabled.
func parentOf(pid int) (int, error) {
	var info C.struct_proc_bsdinfo
	size := C.int(unsafe.Sizeof(info))
	n := C.proc_pidinfo(C.int(pid), C.PROC_PIDTBSDINFO, 0, unsafe.Pointer(&info), size)
	if n != size {
		return 0, fmt.Errorf("proctree: proc_pidinfo(pid=%d) returned %d, want %d", pid, n, size)
	}
	return int(info.pbi_ppid), nil
}
