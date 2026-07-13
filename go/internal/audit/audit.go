package audit

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

type auditEntry struct {
	Timestamp string      `json:"timestamp"`
	RequestID string      `json:"request_id"`
	Method    string      `json:"method"`
	URI       string      `json:"uri"`
	Decision  string      `json:"decision"`
	Reason    string      `json:"reason"`
	Extra     interface{} `json:"extra,omitempty"`
}

func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	return &Logger{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return fmt.Sprintf("%x", b)
}

func (l *Logger) Allow(method, uri, reason string, extra map[string]interface{}) {
	l.log("ALLOW", method, uri, reason, extra)
}

func (l *Logger) Deny(method, uri, reason string, extra map[string]interface{}) {
	l.log("DENY", method, uri, reason, extra)
}

func (l *Logger) log(decision, method, uri, reason string, extra map[string]interface{}) {
	entry := auditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		RequestID: generateRequestID(),
		Method:    method,
		URI:       uri,
		Decision:  decision,
		Reason:    reason,
		Extra:     extra,
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.enc.Encode(entry); err != nil {
		slog.Error("failed to write audit entry", "error", err)
	}
}

func (l *Logger) Close() error {
	return l.file.Close()
}
