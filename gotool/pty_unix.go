//go:build linux || darwin

package main

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/ssh/terminal"
)

// Termios ioctl request numbers differ per platform.
var (
	tcgetsReq uintptr = 0x5401 // Linux TCGETS
	tcsetsReq uintptr = 0x5402 // Linux TCSETS
)

func init() {
	if runtime.GOOS == "darwin" {
		tcgetsReq = 0x4048741a // TIOCGETA
		tcsetsReq = 0x8048741b // TIOCSETA
	}
}

// makeStdinRaw puts stdin into raw mode and returns the previous state.
func makeStdinRaw() (*syscall.Termios, error) {
	fd := int(os.Stdin.Fd())
	var t syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		tcgetsReq, uintptr(unsafe.Pointer(&t)), 0, 0, 0); errno != 0 {
		return nil, errno
	}
	prev := t
	t.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		tcsetsReq, uintptr(unsafe.Pointer(&t)), 0, 0, 0); errno != 0 {
		return nil, errno
	}
	return &prev, nil
}

func restoreStdin(prev *syscall.Termios) {
	if prev == nil {
		return
	}
	fd := int(os.Stdin.Fd())
	syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		tcsetsReq, uintptr(unsafe.Pointer(prev)), 0, 0, 0) //nolint:errcheck
}

func terminalSize(fd int) (cols, rows int) {
	w, h, err := terminal.GetSize(fd)
	if err != nil {
		return 80, 24
	}
	return w, h
}

// watchResize returns a channel notified on SIGWINCH.
func watchResize() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	return ch
}

func stopResize(ch chan os.Signal) {
	signal.Stop(ch)
	close(ch)
}

// readPasswordTerminal reads a hidden password from the controlling terminal.
func readPasswordTerminal() ([]byte, error) {
	return terminal.ReadPassword(int(os.Stdin.Fd()))
}
