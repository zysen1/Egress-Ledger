package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zysen1/Egress-Ledger/internal/ca"
	"github.com/zysen1/Egress-Ledger/internal/capture"
)

func TestInterceptsTrustedClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-Test") != "1" {
			t.Errorf("header %q", r.Header.Get("X-Test"))
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(b)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	authority, err := ca.Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	capPath := dir + "/cap.jsonl"
	w, err := capture.Create(capPath, "test-agent", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	p := &Proxy{
		CA: authority, Agent: "test-agent", Version: "1.0.0", Capture: w,
		Map: map[string]string{"api.example-agent.test:443": strings.TrimPrefix(upstream.URL, "http://")},
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(authority.CertPEM)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(mustURL(t, "http://"+p.Addr())),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	body := `{"hello":"EL_BAIT_sk-live-egressledger-7f3a9c2e1b"}`
	req, err := http.NewRequest(http.MethodPost, "https://api.example-agent.test/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test", "1")
	req.Header.Set("Authorization", "Bearer super-secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if string(got) != body {
		t.Fatalf("echo %q", got)
	}
	w.Close()
	loaded, err := capture.Load(capPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Flows) != 1 {
		t.Fatalf("flows %d", len(loaded.Flows))
	}
	f := loaded.Flows[0]
	if f.Host != "api.example-agent.test" || f.Path != "/v1/messages" {
		t.Fatalf("flow %+v", f)
	}
	if string(f.Body) != body {
		t.Fatalf("body %q", f.Body)
	}
	if f.BodyBytes != len(body) || f.ReqBytes <= f.BodyBytes {
		t.Fatalf("sizes body %d req %d", f.BodyBytes, f.ReqBytes)
	}
	if f.Status != http.StatusCreated {
		t.Fatalf("recorded status %d", f.Status)
	}
	for _, vals := range f.ReqHeaders {
		for _, v := range vals {
			if strings.Contains(v, "super-secret") {
				t.Fatal("authorization leaked into capture")
			}
		}
	}
}

func TestPinnedClientIsInvisible(t *testing.T) {
	dir := t.TempDir()
	authority, err := ca.Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	capPath := dir + "/cap.jsonl"
	w, err := capture.Create(capPath, "test-agent", "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{CA: authority, Agent: "test-agent", Version: "1.1.0", Capture: w}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(mustURL(t, "http://"+p.Addr())),
		TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()},
	}}
	req, _ := http.NewRequest(http.MethodGet, "https://pinned.example-vendor.test/v1/heartbeat", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("pinned client succeeded")
	}
	client.CloseIdleConnections()
	p.Wait()
	w.Close()
	loaded, err := capture.Load(capPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Flows) != 0 {
		t.Fatalf("pinned client produced a flow: %+v", loaded.Flows)
	}
	if len(loaded.Invisible) != 1 {
		t.Fatalf("invisible %+v", loaded.Invisible)
	}
	inv := loaded.Invisible[0]
	if inv.Host != "pinned.example-vendor.test" || inv.Reason != "cert_pin_or_tls_reject" {
		t.Fatalf("invisible %+v", inv)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
