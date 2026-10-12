//go:build windows

package main

import (
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

type savedState struct{ fd int }

func makeStdinRaw() (*savedState, error) {
	fd := int(os.Stdin.Fd())
	if _, err := terminal.MakeRaw(fd); err != nil {
		return nil, err
	}
	return &savedState{fd: fd}, nil
}

func restoreStdin(s *savedState) {
	_ = s // Windows console state is managed by the terminal package; nothing to do.
}

func terminalSize(fd int) (cols, rows int) {
	w, h, err := terminal.GetSize(fd)
	if err != nil {
		return 80, 24
	}
	return w, h
}

// watchResize polls nothing on Windows (no SIGWINCH); returns a dead channel.
func watchResize() chan os.Signal {
	ch := make(chan os.Signal, 1)
	return ch
}

func stopResize(ch chan os.Signal) { close(ch) }

func readPasswordTerminal() ([]byte, error) {
	return terminal.ReadPassword(int(os.Stdin.Fd()))
}
