//go:build darwin || linux

package costanalytics

import (
	"fmt"
	"os"
	"syscall"
)

func transcriptFileIdentity(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf("fallback:%d:%d", info.Size(), info.ModTime().UnixNano())
	}
	return fmt.Sprintf("%d:%d", uint64(stat.Dev), uint64(stat.Ino))
}
