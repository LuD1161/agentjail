//go:build !windows

package main

import "os"

func currentUID() int {
	return os.Getuid()
}
