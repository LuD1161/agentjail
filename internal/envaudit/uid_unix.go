//go:build !windows

package envaudit

import "os"

func currentUID() int {
	return os.Getuid()
}
