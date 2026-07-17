// Command probe is a minimal AF_UNIX reachability probe for verifying what a
// macOS Seatbelt (sbpl) profile actually mediates.
//
// server: bind+listen on the socket path, echo a banner to each client.
// client: connect() and report the precise outcome (ok / EPERM / other).
//
// Exit codes (client): 0 = connect+read succeeded, 1 = EPERM, 2 = other error.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: probe <server|client> <socket-path>")
		os.Exit(3)
	}
	mode, path := os.Args[1], os.Args[2]

	switch mode {
	case "server":
		_ = os.Remove(path)
		l, err := net.Listen("unix", path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "server listen failed: %v\n", err)
			os.Exit(3)
		}
		defer l.Close()
		fmt.Println("listening")
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("CONTROL-PLANE-REACHED\n"))
			c.Close()
		}

	case "client":
		d := net.Dialer{Timeout: 3 * time.Second}
		c, err := d.Dial("unix", path)
		if err != nil {
			// Classify: EPERM/EACCES means the sandbox mediated the connect().
			if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
				fmt.Printf("DENIED_BY_SANDBOX %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("OTHER_ERROR %v\n", err)
			os.Exit(2)
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, rerr := c.Read(buf)
		if rerr != nil {
			fmt.Printf("CONNECTED_BUT_READ_FAILED %v\n", rerr)
			os.Exit(0)
		}
		fmt.Printf("CONNECT_OK payload=%q\n", string(buf[:n]))
		os.Exit(0)

	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(3)
	}
}
