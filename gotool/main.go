// Command gotool is a small repository helper utility.
//
// It is rebuilt automatically by ./update.sh every time new code changes
// are made in this repository, so the binary always reflects the
// latest source under gotool/.
//
// Usage:
//
//	gotool version            Print build information (version, commit, date)
//	gotool status             Show git working-tree status of the repo root
//	gotool diff [commit]      Show changed files since HEAD or a given ref
//	gotool info               Show information about the repository layout
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Build metadata — injected at compile time via -ldflags by update.sh.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	switch args[0] {
	case "version":
		fmt.Printf("gotool %s (commit %s, built %s)\n", version, commit, buildDate)
	case "status":
		cmdStatus()
	case "diff":
		ref := "HEAD"
		if len(args) > 1 {
			ref = args[1]
		}
		cmdDiff(ref)
	case "info":
		cmdInfo()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", args[0])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gotool - repository helper utility

Commands:
  version          Print build information (version, commit, build date)
  status           Show git working-tree status of the repository root
  diff [ref]       Show files changed since ref (default: HEAD)
  info             Show information about the repository layout
  help             Show this help message
`)
}

// repoRoot returns the directory containing the top-level .git folder.
func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("not inside a git repository: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// runGit executes a git command inside the repository root and echoes its output.
func runGit(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmdStatus() {
	root, err := repoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("repository: %s\n", root)
	if err := runGit(root, "git", "status", "--short", "--branch"); err != nil {
		fmt.Fprintln(os.Stderr, "git status failed:", err)
		os.Exit(1)
	}
}

func cmdDiff(ref string) {
	root, err := repoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, err := exec.Command("git", "-C", root, "diff", "--name-status", ref).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "git diff failed:", err)
		os.Exit(1)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		fmt.Printf("no changes against %s\n", ref)
		return
	}
	fmt.Printf("files changed against %s:\n", ref)
	for _, l := range lines {
		fmt.Println(" ", l)
	}
}

func cmdInfo() {
	root, err := repoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("repository root : %s\n", root)

	entries, err := os.ReadDir(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read repo root:", err)
		os.Exit(1)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			dirs = append(dirs, e.Name())
		}
	}
	fmt.Printf("top-level dirs  : %s\n", strings.Join(dirs, ", "))

	// Count Go sources under gotool/ as a sanity check that the tool
	// itself is present and up to date.
	goFiles := 0
	_ = filepath.Walk(filepath.Join(root, "gotool"), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".go") {
			goFiles++
		}
		return nil
	})
	fmt.Printf("tool go sources : %d file(s) under gotool/\n", goFiles)
}
