// Package proxy is a local HTTP proxy that tunnels CONNECT and presents a
// leaf certificate from the ledger CA. Observed requests are appended to a
// capture. A client that rejects the leaf is recorded as invisible: the
// bytes it meant to send never become visible.
package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zysen1/Egress-Ledger/internal/ca"
	"github.com/zysen1/Egress-Ledger/internal/capture"
)

// Proxy intercepts agent traffic.
type Proxy struct {
	CA      *ca.Authority
	Agent   string
	Version string
	// Map redirects host:port to a local plain-HTTP address. Used by the
	// offline demo so reserved .test names stay on the machine.
	Map     map[string]string
	Capture *capture.Writer

	ln  net.Listener
	srv *http.Server
	wg  sync.WaitGroup
}

// Start listens and serves in the background.
func (p *Proxy) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.ln = ln
	p.srv = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go p.srv.Serve(ln)
	return nil
}

// Addr returns the bound address.
func (p *Proxy) Addr() string {
	return p.ln.Addr().String()
}

// Wait blocks until in-flight CONNECT handlers finish. Call it before
// closing the capture so a rejected handshake is recorded. Hijacked
// connections are not stopped by Close.
func (p *Proxy) Wait() { p.wg.Wait() }

// Close stops accepting connections.
func (p *Proxy) Close() error {
	if p.srv != nil {
		return p.srv.Close()
	}
	return nil
}

// ServeHTTP implements the proxy.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.wg.Add(1)
	defer p.wg.Done()
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	http.Error(w, "egress-ledger proxy accepts CONNECT", http.StatusMethodNotAllowed)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		return
	}
	host, port := splitHost(r.Host)
	leaf, err := p.CA.Leaf(host)
	if err != nil {
		client.Close()
		return
	}
	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = p.Capture.AddInvisible(capture.Invisible{
			Time:    time.Now().UTC(),
			Agent:   p.Agent,
			Version: p.Version,
			Host:    host,
			Port:    port,
			Reason:  invisibleReason(err),
			Detail:  err.Error(),
		})
		tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	p.serveMITM(tlsConn, host, port)
}

func (p *Proxy) serveMITM(conn net.Conn, host, port string) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, capture.MaxBodyBytes+1))
		req.Body.Close()
		if err != nil {
			return
		}
		truncated := false
		if len(body) > capture.MaxBodyBytes {
			body = body[:capture.MaxBodyBytes]
			truncated = true
		}
		flow := capture.Flow{
			ID:          newID(),
			Time:        time.Now().UTC(),
			Agent:       p.Agent,
			Version:     p.Version,
			Method:      req.Method,
			Host:        host,
			Port:        port,
			Path:        req.URL.Path,
			Query:       req.URL.RawQuery,
			ReqHeaders:  redactHeaders(req.Header),
			Body:        body,
			BodyBytes:   len(body),
			ReqBytes:    messageSize(req.Method, requestURI(req), req.Header, body),
			Truncated:   truncated,
			ContentType: req.Header.Get("Content-Type"),
		}
		status, respBytes, upErr, header, respBody := p.roundTrip(req, host, port, body)
		flow.Status = status
		flow.RespBytes = respBytes
		flow.UpstreamError = upErr
		if err := p.Capture.AddFlow(flow); err != nil {
			return
		}
		if upErr != "" {
			msg := "upstream error\n"
			resp := &http.Response{
				StatusCode:    http.StatusBadGateway,
				Status:        "502 Bad Gateway",
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				Body:          io.NopCloser(strings.NewReader(msg)),
				ContentLength: int64(len(msg)),
			}
			resp.Write(conn)
			return
		}
		resp := &http.Response{
			StatusCode:    status,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        header.Clone(),
			Body:          io.NopCloser(strings.NewReader(string(respBody))),
			ContentLength: int64(len(respBody)),
		}
		if resp.Header == nil {
			resp.Header = http.Header{}
		}
		resp.Header.Del("Content-Length")
		resp.Status = http.StatusText(status)
		if err := resp.Write(conn); err != nil {
			return
		}
	}
}

func (p *Proxy) roundTrip(req *http.Request, host, port string, body []byte) (status, respBytes int, upErr string, header http.Header, respBody []byte) {
	key := net.JoinHostPort(host, port)
	var conn net.Conn
	var err error
	if addr, ok := p.Map[key]; ok {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	} else {
		raw, err2 := net.DialTimeout("tcp", key, 10*time.Second)
		if err2 != nil {
			return 0, 0, err2.Error(), nil, nil
		}
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		tlsConn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err = tlsConn.Handshake(); err != nil {
			raw.Close()
			return 0, 0, err.Error(), nil, nil
		}
		_ = tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}
	if err != nil {
		return 0, 0, err.Error(), nil, nil
	}
	defer conn.Close()
	out := req.Clone(req.Context())
	out.RequestURI = ""
	out.URL.Scheme = "http"
	out.URL.Host = key
	out.Body = io.NopCloser(strings.NewReader(string(body)))
	out.ContentLength = int64(len(body))
	if out.Host == "" {
		out.Host = key
	}
	out.Header.Del("Proxy-Connection")
	if err := out.Write(conn); err != nil {
		return 0, 0, err.Error(), nil, nil
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), out)
	if err != nil {
		return 0, 0, err.Error(), nil, nil
	}
	defer resp.Body.Close()
	respBody, err = io.ReadAll(io.LimitReader(resp.Body, capture.MaxBodyBytes))
	if err != nil {
		return resp.StatusCode, 0, err.Error(), resp.Header, nil
	}
	return resp.StatusCode, len(respBody), "", resp.Header, respBody
}

func splitHost(h string) (string, string) {
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		return h, "443"
	}
	return host, port
}

func invisibleReason(err error) string {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline") {
		return "handshake_timeout"
	}
	return "cert_pin_or_tls_reject"
}

func redactHeaders(h http.Header) map[string][]string {
	out := map[string][]string{}
	for k, vals := range h {
		switch strings.ToLower(k) {
		case "authorization", "proxy-authorization", "cookie", "x-api-key":
			out[k] = []string{"***"}
		default:
			out[k] = append([]string(nil), vals...)
		}
	}
	return out
}

func requestURI(req *http.Request) string {
	if req.URL.RawQuery != "" {
		return req.URL.Path + "?" + req.URL.RawQuery
	}
	if req.URL.Path == "" {
		return "/"
	}
	return req.URL.Path
}

// messageSize is a reconstructed HTTP/1.1 size with header names sorted.
func messageSize(method, uri string, header http.Header, body []byte) int {
	n := len(method) + 1 + len(uri) + len(" HTTP/1.1\r\n")
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range header[k] {
			n += len(k) + len(": ") + len(v) + len("\r\n")
		}
	}
	n += len("\r\n") + len(body)
	return n
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
