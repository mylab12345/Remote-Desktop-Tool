package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Session describes one saved remote connection (MobaXterm-style session).
type Session struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // ssh | sftp | rdp | scp
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"` // stored obfuscated (enc:...)
	AuthKey  string `json:"authkey,omitempty"`
	Res      string `json:"res,omitempty"` // RDP resolution, e.g. 1920x1080
	Scale    int    `json:"scale,omitempty"`
	Note     string `json:"note,omitempty"`
}

// sessionsDir returns the vault directory (default: ~/.gotool/sessions).
func sessionsDir() (string, error) {
	if v := os.Getenv("GOTOOL_SESSIONS_DIR"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".gotool", "sessions"), nil
}

// defaultPort returns the conventional port for a session type.
func defaultPort(t string) int {
	switch t {
	case "ssh":
		return 22
	case "rdp":
		return 3389
	case "sftp":
		return 22
	}
	return 0
}

func sessionPath(name string) (string, error) {
	dir, err := sessionsDir()
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("invalid session name %q", name)
	}
	return filepath.Join(dir, name+".json"), nil
}

// loadSession reads and decrypts one session file.
func loadSession(name string) (*Session, error) {
	p, err := sessionPath(name)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("session %q not found", name)
		}
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("corrupt session file %s: %w", p, err)
	}
	s.Password = decryptSecret(s.Password)
	return &s, nil
}

// saveSession writes a session file (password stored obfuscated).
func saveSession(s *Session) error {
	dir, err := sessionsDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p, err := sessionPath(s.Name)
	if err != nil {
		return err
	}
	cp := *s
	cp.Password = encryptSecret(cp.Password)
	raw, err := json.MarshalIndent(&cp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(raw, '\n'), 0o600)
}

// listSessions returns all saved sessions sorted by name.
func listSessions() ([]*Session, error) {
	dir, err := sessionsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Session
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		s, err := loadSession(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", e.Name(), err)
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func deleteSession(name string) error {
	p, err := sessionPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("session %q not found", name)
		}
		return err
	}
	return nil
}

// validate checks required fields and normalizes defaults.
func (s *Session) validate() error {
	switch s.Type {
	case "ssh", "rdp", "sftp", "scp":
	default:
		return fmt.Errorf("unknown session type %q (want ssh|rdp|sftp|scp)", s.Type)
	}
	if s.Host == "" {
		return fmt.Errorf("session %q: host is required", s.Name)
	}
	if s.Port == 0 {
		s.Port = defaultPort(s.Type)
	}
	return nil
}
