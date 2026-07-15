package main

import (
	"os"

	"github.com/LuD1161/agentjail/internal/secretsapp"
)

func main() {
	os.Exit(secretsapp.Run(os.Args[1:]))
}
