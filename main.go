package main

import (
	"os"

	"github.com/onatribar/dockscribe/internal/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
