//go:build !linux && !darwin

package main

import (
	"crypto"
	"fmt"
	"runtime"
)

func setupTunnelCA(ns interface{}) (string, crypto.PrivateKey, func(), error) {
	return "", nil, func() {}, fmt.Errorf("tunnel CA injection not supported on %s", runtime.GOOS)
}
