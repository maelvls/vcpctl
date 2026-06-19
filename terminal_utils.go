package main

import (
	"os"

	"github.com/mattn/go-isatty"
)

// IsInteractiveTerminal checks if the given file descriptor is an interactive terminal.
// It returns false if:
// - The fd is not a TTY (e.g., piped input/output)
// - TERM environment variable is set to "dumb"
func IsInteractiveTerminal(fd uintptr) bool {
	if !isatty.IsTerminal(fd) {
		return false
	}
	// TERM=dumb indicates a non-interactive terminal (CI, automation, etc.)
	return os.Getenv("TERM") != "dumb"
}
