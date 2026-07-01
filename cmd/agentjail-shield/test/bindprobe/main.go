// Command bindprobe is a tiny test helper used by shield_darwin_fixes_test.go
// (FIX2 Approach-B attempt, ADR 0039) to check whether a given sbpl profile,
// applied via sandbox-exec, actually scopes a TCP bind to the loopback
// interface. It is not part of the shield binary itself -- it is built on
// demand by the test and run under sandbox-exec with a candidate profile.
//
// Usage: bindprobe <addr>  (e.g. "127.0.0.1:0" or "0.0.0.0:0")
//
// Prints "<addr>=OK" if the bind succeeds, or "<addr>=DENIED:<err>" if it
// fails (EPERM/EACCES from the sandbox, or any other bind error).
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: bindprobe <addr>")
		os.Exit(2)
	}
	addr := os.Args[1]
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("%s=DENIED:%v\n", addr, err)
		return
	}
	defer l.Close()
	fmt.Printf("%s=OK\n", addr)
}
