package classify

import (
	"testing"
	"time"

	"github.com/zysen1/Egress-Ledger/internal/capture"
)

func TestFixtureExact(t *testing.T) {
	m := EvaluateFixture()
	if len(m.Failures) > 0 {
		t.Fatalf("fixture failures: %v", m.Failures)
	}
	if m.SecretCases != 20 || m.SecretExact != 20 {
		t.Fatalf("secrets %+v", m)
	}
	if m.GitCases != 6 || m.GitExact != 6 {
		t.Fatalf("git %+v", m)
	}
	if m.FileCases != 5 || m.FileExact != 5 {
		t.Fatalf("files %+v", m)
	}
	if m.SecretPrecision != 1 || m.SecretRecall != 1 || m.GitAccuracy != 1 || m.FileAccuracy != 1 {
		t.Fatalf("scores %+v", m)
	}
}

func TestBaitNotDoubleLabeled(t *testing.T) {
	got := DetectPatterns([]byte("OPENAI_API_KEY=EL_BAIT_sk-live-egressledger-7f3a9c2e1b\n"))
	if len(got) != 1 || got[0] != "bait" {
		t.Fatalf("got %v", got)
	}
}

func TestRedactHidesBait(t *testing.T) {
	const raw = "EL_BAIT_sk-live-egressledger-7f3a9c2e1b"
	r := redact(raw)
	if r == raw || len(r) >= len(raw) {
		t.Fatalf("redact %q", r)
	}
}

func TestCompareAddsDomain(t *testing.T) {
	old := &Report{Version: "1.0.0", Categories: []CategoryStat{{Name: "inference", BodyBytes: 10}}}
	next := &Report{
		Version:    "1.1.0",
		Domains:    []DomainStat{{Host: "uploads.example-vendor.test"}},
		Categories: []CategoryStat{{Name: "inference", BodyBytes: 10}, {Name: "upload", BodyBytes: 40}},
		Secrets:    []SecretHit{{Pattern: "bait", Host: "uploads.example-vendor.test", Redacted: "EL_B…1b", Source: "body"}},
	}
	// Fill zero categories the way Analyze does, so Compare's fixed order is stable.
	old.Categories = fullCats(map[string]int{"inference": 10})
	next.Categories = fullCats(map[string]int{"inference": 10, "upload": 40})
	d := Compare(old, next)
	if len(d.DomainsAdded) != 1 || d.DomainsAdded[0] != "uploads.example-vendor.test" {
		t.Fatalf("domains %+v", d.DomainsAdded)
	}
	if len(d.SecretsAdded) != 1 {
		t.Fatalf("secrets %+v", d.SecretsAdded)
	}
	var upload int
	for _, c := range d.Categories {
		if c.Name == "upload" {
			upload = c.Delta
		}
	}
	if upload != 40 {
		t.Fatalf("upload delta %d", upload)
	}
}

func fullCats(m map[string]int) []CategoryStat {
	var out []CategoryStat
	for _, name := range Categories {
		out = append(out, CategoryStat{Name: name, BodyBytes: m[name]})
	}
	return out
}

func TestAnalyzeSums(t *testing.T) {
	cap := &capture.Capture{Session: capture.Session{Agent: "a", Version: "1"}}
	cap.Flows = []capture.Flow{
		{ID: "1", Host: "API.Example-Agent.Test.", Method: "POST", Path: "/v1/messages", ContentType: "application/json", Body: []byte(`{"m":1}`), BodyBytes: 7, ReqBytes: 20},
		{ID: "2", Host: "telemetry.example-agent.test", Method: "POST", Path: "/v1/events", ContentType: "application/json", Body: []byte(`{"e":1}`), BodyBytes: 7, ReqBytes: 20},
	}
	cap.Invisible = []capture.Invisible{{Host: "Pinned.Example-Vendor.Test", Port: "443", Reason: "cert_pin_or_tls_reject", Detail: "bad cert"}}
	rep := Analyze(cap, nil, time.Unix(0, 0).UTC())
	if rep.BodyBytes != 14 || rep.FlowCount != 2 {
		t.Fatalf("totals %+v", rep)
	}
	if len(rep.Invisible) != 1 || rep.Invisible[0].Host != "pinned.example-vendor.test" {
		t.Fatalf("invisible %+v", rep.Invisible)
	}
	if rep.Domains[0].Host != "api.example-agent.test" {
		t.Fatalf("host %s", rep.Domains[0].Host)
	}
	var sum int
	for _, c := range rep.Categories {
		sum += c.BodyBytes
	}
	if sum != rep.BodyBytes {
		t.Fatalf("category sum %d", sum)
	}
}
