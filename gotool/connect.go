package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// dialSSH opens an SSH connection for a session, trying key auth first,
// then saved password, then interactive prompt.
func dialSSH(s *Session, hostOverride string, portOverride int, askPassword bool) (*ssh.Client, error) {
	host := s.Host
	if hostOverride != "" {
		host = hostOverride
	}
	port := s.Port
	if portOverride != 0 {
		port = portOverride
	}
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	var auth []ssh.AuthMethod

	// 1) Explicit private key from the session record.
	if s.AuthKey != "" {
		keyBytes, err := os.ReadFile(s.AuthKey)
		if err != nil {
			return nil, fmt.Errorf("reading key %s: %w", s.AuthKey, err)
		}
		var signer ssh.Signer
		if strings.Contains(string(keyBytes), "ENCRYPTED") {
			fmt.Printf("Passphrase for key %s: ", s.AuthKey)
			pass, err := readPasswordTerminal()
			if err != nil {
				return nil, err
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, pass)
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parsing key %s: %w", s.AuthKey, err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	// 2) Default key files (~/.ssh/id_*).
	if s.AuthKey == "" {
		if home, err := os.UserHomeDir(); err == nil {
			for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
				p := home + "/.ssh/" + name
				if keyBytes, err := os.ReadFile(p); err == nil {
					if signer, err := ssh.ParsePrivateKey(keyBytes); err == nil {
						auth = append(auth, ssh.PublicKeys(signer))
					}
				}
			}
		}
	}

	// 3) Saved password.
	if s.Password != "" {
		auth = append(auth, ssh.Password(s.Password))
	}

	// 4) Interactive prompt fallback (keyboard-interactive + password).
	if askPassword && s.Password == "" {
		promptFn := func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
			for i, q := range questions {
				var b []byte
				if i < len(echos) && echos[i] {
					fmt.Print(q)
					os.Stdout.Sync()
					var line string
					if _, err := fmt.Scanln(&line); err != nil {
						return nil, err
					}
					b = []byte(line)
				} else {
					fmt.Print(q)
					b, err = readPasswordTerminal()
					fmt.Println()
					if err != nil {
						return nil, err
					}
				}
				answers = append(answers, string(b))
			}
			return answers, nil
		}
		auth = append(auth, ssh.KeyboardInteractive(promptFn))
	}

	cfg := &ssh.ClientConfig{
		User:            s.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s as %s: %w", addr, s.User, err)
	}
	return client, nil
}

// interactiveShell runs a terminal-backed remote shell over SSH.
func interactiveShell(client *ssh.Client) error {
	cols, rows := terminalSize(int(os.Stdin.Fd()))
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}

	stdinRaw, err := makeStdinRaw()
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: raw terminal mode unavailable (%v), using line mode\n", err)
	} else {
		defer restoreStdin(stdinRaw)
	}

	outPipe, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	errPipe, err := session.StderrPipe()
	if err != nil {
		return err
	}
	inPipe, err := session.StdinPipe()
	if err != nil {
		return err
	}

	if err := session.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}

	go pump(outPipe, os.Stdout)
	go pump(errPipe, os.Stderr)
	go pump(os.Stdin, discardWriter{inPipe})

	resizeCh := watchResize()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range resizeCh {
			c, r := terminalSize(int(os.Stdin.Fd()))
			_ = session.WindowChange(r, c)
		}
	}()

	err = session.Wait()
	stopResize(resizeCh)
	<-done
	return err
}

// runRemoteCommand executes one command over SSH and streams its output.
func runRemoteCommand(client *ssh.Client, command string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
	err = session.Run(command)
	var ee *ssh.ExitError
	if ok := asExitError(err, &ee); ok {
		os.Exit(ee.ExitStatus())
	}
	return err
}

func asExitError(err error, target **ssh.ExitError) bool {
	if err == nil {
		return false
	}
	if ee, ok := err.(*ssh.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// ---- external clients (RDP / SFTP fallbacks) -------------------------------

func haveBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// launchRDP shells out to an RDP client (xfreerdp or mstsc-style wrapper).
func launchRDP(s *Session, extra []string) error {
	client := ""
	for _, cand := range []string{"xfreerdp", "wfreerdp", "sneaky-rdp", "mstsc"} {
		if haveBinary(cand) {
			client = cand
			break
		}
	}
	if client == "" {
		return fmt.Errorf("no RDP client found — install FreeRDP:\n" +
			"    Debian/Ubuntu: sudo apt install freerdp2-x11\n" +
			"    macOS:         brew install freerdp\n" +
			"    Windows:       use built-in mstsc.exe")
	}
	res := s.Res
	if res == "" {
		res = "1600x900"
	}
	args := []string{
		"/v:" + s.Host,
		fmt.Sprintf("/port:%d", portOrDefault(s.Port, 3389)),
		"/size:" + res,
	}
	if s.User != "" {
		args = append(args, "/u:"+s.User)
	}
	if s.Password != "" {
		args = append(args, "/p:"+s.Password)
	}
	if s.Scale > 0 {
		args = append(args, fmt.Sprintf("/scale:%d", s.Scale))
	}
	args = append(args, "/cert:ignore", "/gdi:sw")
	args = append(args, extra...)
	cmd := exec.Command(client, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	fmt.Printf("launching %s %s\n", client, strings.Join(redactArgs(args, s.Password), " "))
	return cmd.Run()
}

func portOrDefault(p, def int) int {
	if p != 0 {
		return p
	}
	return def
}

func redactArgs(args []string, secret string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if secret != "" && strings.Contains(a, secret) {
			out[i] = "[redacted]"
		} else {
			out[i] = a
		}
	}
	return out
}

// launchSFTPGUI opens the system file browser at an sftp:// URL (MobaXterm
// style SFTP side panel). Falls back to printing the URL.
func launchSFTPGUI(s *Session) error {
	url := fmt.Sprintf("sftp://%s@%s:%d/", s.User, s.Host, portOrDefault(s.Port, 22))
	var cmd *exec.Cmd
	switch {
	case haveBinary("xdg-open"):
		cmd = exec.Command("xdg-open", url)
	case haveBinary("open"): // macOS
		cmd = exec.Command("open", url)
	default:
		fmt.Println(url)
		return nil
	}
	fmt.Printf("opening SFTP browser: %s\n", url)
	return cmd.Start()
}

// pump copies src -> dst until EOF (used for terminal I/O multiplexing).
func pump(src io.Reader, dst io.Writer) {
	_, _ = io.Copy(dst, src)
}

// discardWriter forwards writes and ignores errors (stdin -> remote pipe;
// errors happen naturally when the session closes).
type discardWriter struct{ w io.Writer }

func (d discardWriter) Write(p []byte) (int, error) { return d.w.Write(p) }
