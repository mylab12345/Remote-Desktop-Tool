package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// parseTarget accepts "name", "[user@]host[:port]" or "ssh://[user@]host[:port]".
func parseTarget(target string) (name, user, host string, port int) {
	t := target
	if strings.HasPrefix(t, "ssh://") {
		t = strings.TrimPrefix(t, "ssh://")
	}
	if i := strings.Index(t, "@"); i >= 0 {
		user = t[:i]
		t = t[i+1:]
	}
	if i := strings.LastIndex(t, ":"); i >= 0 && !strings.Contains(t[i:], "/") {
		p, err := strconv.Atoi(t[i+1:])
		if err == nil {
			port = p
			t = t[:i]
		} else {
			t = "" // invalid port -> treat whole thing as host (will fail below)
		}
	}
	host = t
	return "", user, host, port
}

// cmdNew creates a session. Usage:
//
//	gotool new <name> --type ssh|rdp|sftp|scp --host H [--port P] [--user U]
//	               [--password P | --ask-password] [--key PATH]
//	               [--res WxH] [--scale N] [--note TEXT]
func cmdNew(args []string) {
	s := &Session{}
	flags := map[string]string{}
	positionals := []string{}
	askPw := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--ask-password":
			askPw = true
		case strings.HasPrefix(a, "--"):
			key := strings.TrimPrefix(a, "--")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[key] = args[i+1]
				i++
			} else {
				failf("flag %s requires a value", a)
			}
		default:
			positionals = append(positionals, a)
		}
	}

	if len(positionals) == 0 {
		failf("usage: gotool new <name> --type ssh|rdp|sftp|scp --host HOST [options]")
	}
	s.Name = positionals[0]
	s.Type = flags["type"]
	s.Host = flags["host"]
	s.User = flags["user"]
	s.AuthKey = flags["key"]
	s.Res = flags["res"]
	s.Note = flags["note"]
	s.Password = flags["password"]
	if v := flags["port"]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			failf("invalid --port: %v", err)
		}
		s.Port = p
	}
	if v := flags["scale"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			failf("invalid --scale: %v", err)
		}
		s.Scale = n
	}
	if s.Type == "" {
		s.Type = guessType(s.Port, s.Host)
		fmt.Fprintf(os.Stderr, "note: --type not given, guessed %q\n", s.Type)
	}
	if askPw {
		fmt.Print("Password: ")
		b, err := readPasswordTerminal()
		fmt.Println()
		if err != nil {
			failf("reading password: %v", err)
		}
		s.Password = string(b)
	}
	if err := s.validate(); err != nil {
		failf("%v", err)
	}
	if _, err := loadSession(s.Name); err == nil {
		failf("session %q already exists (use 'gotool edit %s' or delete it first)", s.Name, s.Name)
	}
	if err := saveSession(s); err != nil {
		failf("%v", err)
	}
	fmt.Printf("saved session %q (%s://%s)\n", s.Name, s.Type, addrOf(s))
}

func guessType(port int, host string) string {
	if port == 3389 {
		return "rdp"
	}
	return "ssh"
}

func addrOf(s *Session) string {
	if s.User != "" {
		return fmt.Sprintf("%s@%s:%d", s.User, s.Host, s.Port)
	}
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// cmdEdit updates fields of an existing session (same flags as new).
func cmdEdit(args []string) {
	if len(args) == 0 {
		failf("usage: gotool edit <name> [--host H] [--port P] [--user U] [--password P|--ask-password] [--key PATH] [--res WxH] [--scale N] [--note TEXT] [--type T]")
	}
	s, err := loadSession(args[0])
	if err != nil {
		failf("%v", err)
	}
	rest := args[1:]
	flags := map[string]string{}
	askPw := false
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--ask-password":
			askPw = true
		case strings.HasPrefix(a, "--"):
			key := strings.TrimPrefix(a, "--")
			if i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "--") {
				flags[key] = rest[i+1]
				i++
			} else {
				failf("flag %s requires a value", a)
			}
		default:
			failf("unexpected argument %q", a)
		}
	}
	if v, ok := flags["type"]; ok {
		s.Type = v
	}
	if v, ok := flags["host"]; ok {
		s.Host = v
	}
	if v, ok := flags["user"]; ok {
		s.User = v
	}
	if v, ok := flags["key"]; ok {
		s.AuthKey = v
	}
	if v, ok := flags["res"]; ok {
		s.Res = v
	}
	if v, ok := flags["note"]; ok {
		s.Note = v
	}
	if v, ok := flags["password"]; ok {
		s.Password = v
	}
	if v, ok := flags["port"]; ok {
		p, err := strconv.Atoi(v)
		if err != nil {
			failf("invalid --port: %v", err)
		}
		s.Port = p
	}
	if v, ok := flags["scale"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			failf("invalid --scale: %v", err)
		}
		s.Scale = n
	}
	if askPw {
		fmt.Print("Password: ")
		b, err := readPasswordTerminal()
		fmt.Println()
		if err != nil {
			failf("reading password: %v", err)
		}
		s.Password = string(b)
	}
	if err := s.validate(); err != nil {
		failf("%v", err)
	}
	if err := saveSession(s); err != nil {
		failf("%v", err)
	}
	fmt.Printf("updated session %q\n", s.Name)
}

// cmdList shows saved sessions like MobaXterm's session browser tree.
func cmdList() {
	list, err := listSessions()
	if err != nil {
		failf("%v", err)
	}
	dir, _ := sessionsDir()
	if len(list) == 0 {
		fmt.Printf("no saved sessions (vault: %s)\n", dir)
		fmt.Println("create one with:  gotool new myserver --type ssh --host 10.0.0.5 --user root")
		return
	}
	var byType = map[string][]*Session{}
	for _, s := range list {
		byType[s.Type] = append(byType[s.Type], s)
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sortStrings(types)
	fmt.Printf("sessions (vault: %s)\n", dir)
	for _, t := range types {
		fmt.Printf("  %s\n", strings.ToUpper(t))
		for _, s := range byType[t] {
			auth := "password"
			if s.AuthKey != "" {
				auth = "key:" + s.AuthKey
			} else if s.Password == "" {
				auth = "agent/interactive"
			}
			extra := ""
			if t == "rdp" && s.Res != "" {
				extra = " res=" + s.Res
			}
			fmt.Printf("    %-20s %-24s auth=%s%s\n", s.Name, addrOf(s), auth, extra)
		}
	}
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// cmdDelete removes a session.
func cmdDelete(args []string) {
	if len(args) == 0 {
		failf("usage: gotool delete <name>")
	}
	if err := deleteSession(args[0]); err != nil {
		failf("%v", err)
	}
	fmt.Printf("deleted session %q\n", args[0])
}

// cmdConnect opens a connection: named session or ad-hoc target.
//
//	gotool connect <name>                 interactive shell / RDP launch
//	gotool connect <name> -- <cmd...>     run remote command over SSH
//	gotool connect [[user@]host[:port]]   ad-hoc SSH connection
func cmdConnect(args []string) {
	if len(args) == 0 {
		failf("usage: gotool connect <session|target> [--force-password] [-- -c \"remote cmd\"]")
	}
	target := args[0]
	rest := args[1:]
	forcePw := false
	var filtered []string
	for _, a := range rest {
		if a == "--force-password" {
			forcePw = true
		} else {
			filtered = append(filtered, a)
		}
	}
	rest = filtered

	s, fromVault := loadByNameOrAdhoc(target)
	if err := s.validate(); err != nil {
		failf("%v", err)
	}

	switch s.Type {
	case "rdp":
		if err := launchRDP(s, rest); err != nil {
			failf("%v", err)
		}
	case "sftp":
		if err := launchSFTPGUI(s); err != nil {
			failf("%v", err)
		}
	case "scp":
		failf("scp transfer: use 'gotool get/put' helpers (planned) — or connect via ssh and use scp manually")
	default: // ssh
		client, err := dialSSH(s, "", 0, forcePw || (!fromVault && s.Password == ""))
		if err != nil {
			failf("%v", err)
		}
		defer client.Close()
		fmt.Printf("connected to %s (%s)\n", addrOf(s), s.Name)
		if len(rest) > 0 {
			cmdline := strings.Join(rest, " ")
			if err := runRemoteCommand(client, cmdline); err != nil {
				failf("%v", err)
			}
			return
		}
		if err := interactiveShell(client); err != nil {
			if ee, ok := err.(*ssh_ExitErrorInfo); ok {
				os.Exit(ee.Code)
			}
			fmt.Fprintln(os.Stderr, "session ended:", err)
		}
	}
}

// ssh_ExitErrorInfo mirrors exit status propagation done inside
// runRemoteCommand (which calls os.Exit directly); kept for clarity.
type ssh_ExitErrorInfo struct{ Code int }

func (e *ssh_ExitErrorInfo) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

func loadByNameOrAdhoc(target string) (*Session, bool) {
	if s, err := loadSession(target); err == nil {
		return s, true
	}
	_, user, host, port := parseTarget(target)
	if host == "" {
		failf("unknown session %q and not a valid host/target", target)
	}
	if user == "" {
		user = currentUser()
	}
	s := &Session{Name: host, Type: "ssh", Host: host, Port: port, User: user}
	if port == 0 {
		s.Port = 22
	}
	return s, false
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	r := bufio.NewReader(os.Stdin)
	_ = r
	return "root"
}

func failf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
