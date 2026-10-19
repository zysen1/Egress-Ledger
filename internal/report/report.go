// Package report renders a transparency report. The page describes observed
// egress. It is not a firewall and it does not claim to have blocked traffic.
package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/zysen1/Egress-Ledger/internal/classify"
)

//go:embed page.html
var pageHTML string

// Page is the view model for the nutrition-label report.
type Page struct {
	Heading        string
	Chinese        string
	Lede           string
	Meta           string
	PunchTitle     string
	PunchLines     []string
	Labels         []Label
	ShowDiff       bool
	Diff           []DiffLine
	DomainsAdded   string
	DomainsRemoved string
	Secrets        []SecretRow
	Files          []FileRow
	Git            []GitRow
	Invisible      []InvisibleRow
	Domains        []DomainRow
	Methodology    string
	Foot           string
}

// Label is one version's nutrition panel.
type Label struct {
	Version        string
	Agent          string
	Flows          int
	BodyBytes      int
	ReqBytes       int
	DomainCount    int
	SecretCount    int
	FileCount      int
	GitCount       int
	InvisibleCount int
	Rows           []Bar
}

// Bar is one category row.
type Bar struct {
	Name  string
	Bytes int
	Pct   int
}

// DiffLine is one category delta.
type DiffLine struct {
	Name  string
	Old   int
	New   int
	Delta string
	Up    bool
}

// SecretRow is one redacted secret finding.
type SecretRow struct {
	Pattern  string
	Host     string
	Where    string
	Redacted string
}

// FileRow is one full-file finding.
type FileRow struct {
	Rel    string
	Host   string
	Source string
	Size   int
	SHA    string
}

// GitRow is one git object.
type GitRow struct {
	Kind   string
	Object string
	Host   string
	Size   int
	Hash   string
}

// InvisibleRow is one host whose body was not observed.
type InvisibleRow struct {
	Host     string
	Reason   string
	Attempts int
}

// DomainRow is one contacted host.
type DomainRow struct {
	Host       string
	Requests   int
	Body       int
	Categories string
}

// LabelFrom builds a nutrition panel.
func LabelFrom(rep *classify.Report) Label {
	max := 0
	for _, c := range rep.Categories {
		if c.BodyBytes > max {
			max = c.BodyBytes
		}
	}
	label := Label{
		Version:        rep.Version,
		Agent:          rep.Agent,
		Flows:          rep.FlowCount,
		BodyBytes:      rep.BodyBytes,
		ReqBytes:       rep.ReqBytes,
		DomainCount:    len(rep.Domains),
		SecretCount:    len(rep.Secrets),
		FileCount:      len(rep.Files),
		GitCount:       gitObjects(rep),
		InvisibleCount: len(rep.Invisible),
	}
	for _, c := range rep.Categories {
		pct := 0
		if max > 0 {
			pct = c.BodyBytes * 100 / max
		}
		label.Rows = append(label.Rows, Bar{Name: c.Name, Bytes: c.BodyBytes, Pct: pct})
	}
	return label
}

func gitObjects(rep *classify.Report) int {
	n := 0
	for _, g := range rep.Git {
		if g.Kind != "smart-http" {
			n++
		}
	}
	return n
}

// PageFromReports fills a combined page. Findings are the union, with the
// newer version first in each table via the order already stored on each report.
func PageFromReports(old, newer *classify.Report, diff *classify.Diff, meta string, punch []string) Page {
	p := basePage(meta, punch)
	if old != nil {
		p.Labels = append(p.Labels, LabelFrom(old))
	}
	p.Labels = append(p.Labels, LabelFrom(newer))
	p.Secrets = append(rowsSecrets(old), rowsSecrets(newer)...)
	p.Files = append(rowsFiles(old), rowsFiles(newer)...)
	p.Git = append(rowsGit(old), rowsGit(newer)...)
	p.Invisible = append(rowsInv(old), rowsInv(newer)...)
	p.Domains = append(rowsDomains(old), rowsDomains(newer)...)
	if diff != nil {
		p.ShowDiff = true
		for _, c := range diff.Categories {
			line := DiffLine{Name: c.Name, Old: c.Old, New: c.New, Delta: formatDelta(c.Delta), Up: c.Delta > 0}
			p.Diff = append(p.Diff, line)
		}
		p.DomainsAdded = joinOrNone(diff.DomainsAdded)
		p.DomainsRemoved = joinOrNone(diff.DomainsRemoved)
	}
	return p
}

func basePage(meta string, punch []string) Page {
	return Page{
		Heading:     "Outbound nutrition label",
		Chinese:     "外发流量透明度报告，不是防火墙。",
		Lede:        "What this coding agent sent off the machine, by version. This is a transparency report, not a firewall. Egress Ledger records and compares. It does not block requests. A firewall such as pipelock is a different tool.",
		Meta:        meta,
		PunchTitle:  "Where it went",
		PunchLines:  punch,
		Methodology: classify.Methodology,
		Foot:        "Invisible means the client opened a tunnel and rejected the ledger CA, which is what certificate pinning looks like from this proxy. Those bytes are not in the totals. Traffic that never used the proxy is outside this report.",
	}
}

func rowsSecrets(rep *classify.Report) []SecretRow {
	if rep == nil {
		return nil
	}
	var out []SecretRow
	for _, s := range rep.Secrets {
		where := s.Source
		if s.Object != "" {
			where = s.Source + " " + s.Object
		}
		where = rep.Version + " · " + where
		out = append(out, SecretRow{Pattern: s.Pattern, Host: s.Host, Where: where, Redacted: s.Redacted})
	}
	return out
}

func rowsFiles(rep *classify.Report) []FileRow {
	if rep == nil {
		return nil
	}
	var out []FileRow
	for _, f := range rep.Files {
		sum := f.SHA256
		if len(sum) > 12 {
			sum = sum[:12]
		}
		out = append(out, FileRow{Rel: f.Rel, Host: f.Host, Source: rep.Version + " · " + f.Source, Size: f.Size, SHA: sum})
	}
	return out
}

func rowsGit(rep *classify.Report) []GitRow {
	if rep == nil {
		return nil
	}
	var out []GitRow
	for _, g := range rep.Git {
		if g.Kind == "smart-http" {
			continue
		}
		obj := g.Object
		if obj == "" {
			obj = "—"
		}
		hash := g.Hash
		if len(hash) > 12 {
			hash = hash[:12]
		}
		out = append(out, GitRow{Kind: g.Kind, Object: obj, Host: g.Host, Size: g.Size, Hash: hash})
	}
	return out
}

func rowsInv(rep *classify.Report) []InvisibleRow {
	if rep == nil {
		return nil
	}
	var out []InvisibleRow
	for _, inv := range rep.Invisible {
		out = append(out, InvisibleRow{Host: inv.Host + " (" + rep.Version + ")", Reason: inv.Reason, Attempts: inv.Attempts})
	}
	return out
}

func rowsDomains(rep *classify.Report) []DomainRow {
	if rep == nil {
		return nil
	}
	var out []DomainRow
	for _, d := range rep.Domains {
		var cats []string
		for _, name := range classify.Categories {
			if d.Categories[name] > 0 {
				cats = append(cats, fmt.Sprintf("%s %d B", name, d.Categories[name]))
			}
		}
		out = append(out, DomainRow{
			Host:       d.Host + " (" + rep.Version + ")",
			Requests:   d.Requests,
			Body:       d.BodyBytes,
			Categories: strings.Join(cats, ", "),
		})
	}
	return out
}

func formatDelta(n int) string {
	if n > 0 {
		return fmt.Sprintf("+%d B", n)
	}
	return fmt.Sprintf("%d B", n)
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

// RenderHTML executes the report template.
func RenderHTML(p Page) ([]byte, error) {
	tpl, err := template.New("page").Parse(pageHTML)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteJSON encodes v with indentation.
func WriteJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
