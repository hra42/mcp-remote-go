package auth

import (
	"fmt"
	"os/exec"
	"runtime"
)

// OpenBrowser opens the given URL in the user's default browser.
func OpenBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "linux":
		cmd = "xdg-open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		return fmt.Errorf("auth: unsupported platform %s", runtime.GOOS)
	}

	return exec.Command(cmd, args...).Start()
}
