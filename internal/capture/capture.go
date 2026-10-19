// Package capture stores intercepted flows as JSONL. Bodies are base64 so
// pack bytes survive. Authorization and cookie headers are redacted before
// they touch disk; the body is kept because the report's job is to show
// what left the machine.
package capture

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

const MaxBodyBytes = 8 << 20

// Flow is one observed HTTP request inside a tunneled connection.
type Flow struct {
	Record        string              `json:"record"`
	ID            string              `json:"id"`
	Time          time.Time           `json:"time"`
	Agent         string              `json:"agent,omitempty"`
	Version       string              `json:"version,omitempty"`
	Method        string              `json:"method"`
	Host          string              `json:"host"`
	Port          string              `json:"port"`
	Path          string              `json:"path"`
	Query         string              `json:"query,omitempty"`
	ReqHeaders    map[string][]string `json:"req_headers,omitempty"`
	Body          []byte              `json:"-"`
	BodyB64       string              `json:"req_body_b64,omitempty"`
	BodyBytes     int                 `json:"body_bytes"`
	ReqBytes      int                 `json:"req_bytes"`
	Truncated     bool                `json:"truncated,omitempty"`
	Status        int                 `json:"status"`
	RespBytes     int                 `json:"resp_bytes"`
	UpstreamError string              `json:"upstream_error,omitempty"`
	ContentType   string              `json:"content_type,omitempty"`
}

// Invisible is a tunnel that opened but yielded no HTTP request because
// the client rejected the injected certificate (or the handshake timed out).
type Invisible struct {
	Record  string    `json:"record"`
	Time    time.Time `json:"time"`
	Agent   string    `json:"agent,omitempty"`
	Version string    `json:"version,omitempty"`
	Host    string    `json:"host"`
	Port    string    `json:"port"`
	Reason  string    `json:"reason"`
	Detail  string    `json:"detail,omitempty"`
}

// Session is the first record of a capture file.
type Session struct {
	Record  string    `json:"record"`
	Agent   string    `json:"agent"`
	Version string    `json:"version"`
	Started time.Time `json:"started"`
}

// Capture is a loaded session.
type Capture struct {
	Session   Session
	Flows     []Flow
	Invisible []Invisible
}

// Writer appends records to a JSONL file.
type Writer struct {
	mu sync.Mutex
	f  *os.File
}

// Create truncates path and writes the session header.
func Create(path, agent, version string) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f}
	if err := w.write(Session{Record: "session", Agent: agent, Version: version, Started: time.Now().UTC()}); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

// AddFlow writes one flow.
func (w *Writer) AddFlow(flow Flow) error {
	flow.Record = "flow"
	if len(flow.Body) > 0 {
		flow.BodyB64 = base64.StdEncoding.EncodeToString(flow.Body)
	}
	return w.write(flow)
}

// AddInvisible writes one rejected tunnel.
func (w *Writer) AddInvisible(inv Invisible) error {
	inv.Record = "invisible"
	return w.write(inv)
}

func (w *Writer) write(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.f.Write(b)
	if err != nil {
		return err
	}
	return w.f.Sync()
}

// Close closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

// Load reads a JSONL capture.
func Load(path string) (*Capture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cap Capture
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), MaxBodyBytes*2)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		var head struct {
			Record string `json:"record"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			return nil, fmt.Errorf("capture: line %d: %w", line, err)
		}
		switch head.Record {
		case "session":
			if err := json.Unmarshal(raw, &cap.Session); err != nil {
				return nil, err
			}
		case "flow":
			var flow Flow
			if err := json.Unmarshal(raw, &flow); err != nil {
				return nil, err
			}
			if flow.BodyB64 != "" {
				b, err := base64.StdEncoding.DecodeString(flow.BodyB64)
				if err != nil {
					return nil, fmt.Errorf("capture: line %d: body: %w", line, err)
				}
				flow.Body = b
			}
			cap.Flows = append(cap.Flows, flow)
		case "invisible":
			var inv Invisible
			if err := json.Unmarshal(raw, &inv); err != nil {
				return nil, err
			}
			cap.Invisible = append(cap.Invisible, inv)
		default:
			return nil, fmt.Errorf("capture: line %d: unknown record %q", line, head.Record)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cap.Session.Record == "" {
		return nil, errors.New("capture: missing session record")
	}
	return &cap, nil
}
