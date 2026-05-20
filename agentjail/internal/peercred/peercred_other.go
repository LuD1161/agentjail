//go:build !darwin && !linux

package peercred

import "net"

func getCreds(_ *net.UnixConn) (Creds, error) { return Creds{}, ErrUnsupported }
