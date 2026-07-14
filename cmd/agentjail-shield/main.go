package main

import (
	"os"

	"github.com/LuD1161/agentjail/internal/shieldapp"
)

func main() {
	os.Exit(shieldapp.Run(os.Args[1:]))
}
