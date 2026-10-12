package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Passwords are stored in session files obfuscated with a machine-derived
// XOR stream ("enc:base64"). This is intentionally NOT strong encryption —
// it only avoids plaintext passwords on disk, mirroring how lightweight
// session managers handle saved credentials. For real protection, keep the
// vault directory private (0700) or use ssh-agent / key-based auth.

const encPrefix = "enc:"

func keystream(n int) []byte {
	material := fmt.Sprintf("gotool-vault:%s", hostnameSafe())
	if v := os.Getenv("GOTOOL_VAULT_KEY"); v != "" {
		material += ":" + v
	}
	seed := sha256.Sum256([]byte(material))
	out := make([]byte, 0, n+1)
	counter := byte(0)
	for len(out) < n {
		block := sha256.Sum256(append(append([]byte{}, seed[:]...), counter))
		out = append(out, block[:]...)
		counter++
	}
	return out[:n]
}

func hostnameSafe() string {
	h, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return h
}

// xorBytes applies the keystream to data (symmetric).
func xorBytes(data []byte) []byte {
	ks := keystream(len(data))
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ ks[i]
	}
	return out
}

func encryptSecret(plain string) string {
	if plain == "" || strings.HasPrefix(plain, encPrefix) {
		return plain
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		nonce = []byte(hostnameSafe())
	}
	body := append(nonce, xorBytesWithNonce([]byte(plain), nonce)...)
	return encPrefix + base64.StdEncoding.EncodeToString(body)
}

func decryptSecret(stored string) string {
	if stored == "" || !strings.HasPrefix(stored, encPrefix) {
		return stored
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, encPrefix))
	if err != nil || len(raw) < 8 {
		return "" // unreadable vault entry -> treat as empty
	}
	nonce, body := raw[:8], raw[8:]
	return string(xorBytesWithNonce(body, nonce))
}

func xorBytesWithNonce(data, nonce []byte) []byte {
	material := fmt.Sprintf("gotool-vault:%s:", hostnameSafe())
	if v := os.Getenv("GOTOOL_VAULT_KEY"); v != "" {
		material += v
	}
	seed := sha256.Sum256(append([]byte(material), nonce...))
	out := make([]byte, len(data))
	stream := make([]byte, 0, len(data))
	counter := byte(0)
	for len(stream) < len(data) {
		block := sha256.Sum256(append(append([]byte{}, seed[:]...), counter))
		stream = append(stream, block[:]...)
		counter++
	}
	for i := range data {
		out[i] = data[i] ^ stream[i]
	}
	return out
}
