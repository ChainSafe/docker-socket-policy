package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readEntries(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open audit log: %v", err)
	}
	defer f.Close()

	var entries []map[string]interface{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("invalid audit JSON line: %v", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	return entries
}

func TestLogger_AllowWritesEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	extra := map[string]interface{}{"service": "beacon", "image": "chainsafe/lodestar:next"}
	l.Allow("GET", "/_ping", "request allowed", extra)
	l.Close()

	entries := readEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	assertField(t, e, "decision", "ALLOW")
	assertField(t, e, "method", "GET")
	assertField(t, e, "uri", "/_ping")
	assertField(t, e, "reason", "request allowed")
	if extra, ok := e["extra"].(map[string]interface{}); !ok {
		t.Fatalf("expected extra object, got %T", e["extra"])
	} else {
		if extra["service"] != "beacon" {
			t.Fatalf("expected extra.service beacon, got %v", extra["service"])
		}
		if extra["image"] != "chainsafe/lodestar:next" {
			t.Fatalf("expected extra.image, got %v", extra["image"])
		}
	}
	if e["request_id"] == "" {
		t.Fatal("expected non-empty request_id")
	}
	if e["timestamp"] == "" {
		t.Fatal("expected non-empty timestamp")
	}
}

func TestLogger_DenyWritesEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	l.Deny("POST", "/containers/create", "exec denied by policy", nil)
	l.Close()

	entries := readEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	assertField(t, e, "decision", "DENY")
	assertField(t, e, "method", "POST")
	assertField(t, e, "uri", "/containers/create")
	assertField(t, e, "reason", "exec denied by policy")
}

func TestLogger_MultipleEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	for i := 0; i < 5; i++ {
		l.Allow("GET", "/version", "request allowed", nil)
	}
	l.Close()

	entries := readEntries(t, path)
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
}

func TestLogger_NopLoggerWritesNowhere(t *testing.T) {
	l := NewNopLogger()
	l.Allow("GET", "/_ping", "request allowed", nil)
	l.Deny("POST", "/containers/create", "denied", nil)
	l.Close()
}

func assertField(t *testing.T, e map[string]interface{}, key, expected string) {
	t.Helper()
	if got, ok := e[key].(string); !ok || got != expected {
		t.Fatalf("expected %s=%q, got %v", key, expected, e[key])
	}
}