package audit

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Entry represents a single audit log entry.
type Entry struct {
	Timestamp     string      `json:"timestamp"`
	Service       string      `json:"service,omitempty"`
	Method        string      `json:"method"`
	Path          string      `json:"path"`
	Result        string      `json:"result"`
	Reason        string      `json:"reason,omitempty"`
	Image         string      `json:"image,omitempty"`
	ContainerName string      `json:"container_name,omitempty"`
	Extra         interface{} `json:"extra,omitempty"`
}

// Logger writes JSON audit logs.
type Logger struct {
	file *os.File
	mu   sync.Mutex
}

// NewLogger creates an audit logger writing to the given file path.
func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	return &Logger{file: f}, nil
}

// Close closes the audit log file.
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Allow logs an allowed request.
func (l *Logger) Allow(method, path, reason string, extra map[string]interface{}) {
	l.log(Entry{
		Timestamp: time.Now().Format(time.RFC3339),
		Method:    method,
		Path:      path,
		Result:    "allowed",
		Reason:    reason,
		Extra:     extra,
	})
}

// Deny logs a denied request.
func (l *Logger) Deny(method, path, reason string, extra map[string]interface{}) {
	l.log(Entry{
		Timestamp: time.Now().Format(time.RFC3339),
		Method:    method,
		Path:      path,
		Result:    "denied",
		Reason:    reason,
		Extra:     extra,
	})
}

func (l *Logger) log(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(e)
	if err != nil {
		log.Printf("Failed to marshal audit entry: %v", err)
		return
	}

	if _, err := l.file.Write(append(data, '\n')); err != nil {
		log.Printf("Failed to write audit log: %v", err)
	}
}
