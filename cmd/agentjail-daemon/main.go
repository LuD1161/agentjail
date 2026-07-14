package main

import (
	"os"

	"github.com/LuD1161/agentjail/internal/daemonapp"
)

func main() {
	os.Exit(daemonapp.Run(os.Args[1:]))
}
