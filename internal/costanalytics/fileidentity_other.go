//go:build !darwin && !linux

package costanalytics

import (
	"fmt"
	"os"
)

func transcriptFileIdentity(info os.FileInfo) string {
	return fmt.Sprintf("fallback:%d:%d", info.Size(), info.ModTime().UnixNano())
}
