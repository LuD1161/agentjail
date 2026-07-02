//go:build !linux && !darwin

package main

import (
	"fmt"
	"runtime"
)

func setupTunnelCA(ns interface{}) (string, func(), error) {
	return "", func() {}, fmt.Errorf("tunnel CA injection not supported on %s", runtime.GOOS)
}
