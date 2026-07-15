package main

import (
	"os"

	"github.com/LuD1161/agentjail/internal/netproxyapp"
)

func main() {
	os.Exit(netproxyapp.Run(os.Args[1:]))
}
