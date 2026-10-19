// Package classify turns a capture plus a workspace into a transparency
// report: domains, request body sizes by category, git objects, secret
// patterns, and exact full-file matches. It does not block anything.
package classify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zysen1/Egress-Ledger/internal/capture"
	"github.com/zysen1/Egress-Ledger/internal/gitpack"
)

// MinFileBytes is the smallest workspace file that can count as a full-file
// finding. Shorter files match too often by accident.
const MinFileBytes = 48

// MaxWorkspaceFile is the largest file loaded for exact matching.
const MaxWorkspaceFile = 512 << 10

// Methodology is printed on every report so the numbers stay interpretable.
const Methodology = "Request body bytes are the HTTP body observed after TLS interception. HTTP request bytes are the reconstructed HTTP/1.1 message (request line, headers, body) and exclude TLS framing. Certificate-pinned handshakes that reject the ledger CA are recorded as invisible and contribute no bytes. Secret findings are regex hits on the body and on inflated git objects. Full-file findings are exact byte matches of workspace files of at least 48 bytes. Git findings are smart-HTTP routes and pack objects, including blobs named by trees in the same pack. Egress Ledger records traffic. It does not block it."

// Categories in nutrition-label order.
var Categories = []string{"inference", "telemetry", "api", "upload", "git", "other"}

// File is a workspace file eligible for an exact-content finding.
type File struct {
	Rel  string
	Size int
	SHA  string
	Data []byte
}

// LoadWorkspace reads regular files under root, skipping .git.
func LoadWorkspace(root string) ([]File, error) {
	var out []File
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() == 0 || info.Size() > MaxWorkspaceFile {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		sum := sha256.Sum256(data)
		out = append(out, File{Rel: rel, Size: len(data), SHA: hex.EncodeToString(sum[:]), Data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, nil
}

// SecretHit is one secret-pattern match.
type SecretHit struct {
	Pattern  string `json:"pattern"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	Redacted string `json:"redacted"`
	Source   string `json:"source"`
	FlowID   string `json:"flow_id"`
	Object   string `json:"object,omitempty"`
}

// FileHit is an exact full-file match.
type FileHit struct {
	Rel    string `json:"rel"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
	Source string `json:"source"`
	FlowID string `json:"flow_id"`
}

// GitHit is one observed git object or a smart-HTTP exchange with no pack.
type GitHit struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Object string `json:"object,omitempty"`
	Hash   string `json:"hash,omitempty"`
	Size   int    `json:"size"`
	FlowID string `json:"flow_id"`
	PackOK bool   `json:"pack_checksum_ok,omitempty"`
}

// DomainStat aggregates one host.
type DomainStat struct {
	Host        string         `json:"host"`
	Requests    int            `json:"requests"`
	BodyBytes   int            `json:"body_bytes"`
	ReqBytes    int            `json:"request_bytes"`
	Categories  map[string]int `json:"categories_body_bytes"`
	SecretCount int            `json:"secret_count"`
	FileCount   int            `json:"file_count"`
	GitObjects  int            `json:"git_objects"`
}

// CategoryStat is one nutrition-label row.
type CategoryStat struct {
	Name      string `json:"name"`
	BodyBytes int    `json:"body_bytes"`
	Requests  int    `json:"requests"`
}

// Invisible is a host whose bytes were not observed.
type Invisible struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Reason   string `json:"reason"`
	Detail   string `json:"detail,omitempty"`
	Attempts int    `json:"attempts"`
}

// Report is the per-version transparency record.
type Report struct {
	Agent        string         `json:"agent"`
	Version      string         `json:"version"`
	Generated    time.Time      `json:"generated"`
	FlowCount    int            `json:"flow_count"`
	BodyBytes    int            `json:"body_bytes"`
	ReqBytes     int            `json:"request_bytes"`
	Domains      []DomainStat   `json:"domains"`
	Categories   []CategoryStat `json:"categories"`
	Secrets      []SecretHit    `json:"secrets"`
	Files        []FileHit      `json:"files"`
	Git          []GitHit       `json:"git"`
	Invisible    []Invisible    `json:"invisible"`
	Methodology  string         `json:"methodology"`
	MinFileBytes int            `json:"min_file_bytes"`
}

// Analyze classifies a capture against workspace files.
func Analyze(cap *capture.Capture, files []File, now time.Time) *Report {
	rep := &Report{
		Agent:        cap.Session.Agent,
		Version:      cap.Session.Version,
		Generated:    now.UTC(),
		Methodology:  Methodology,
		MinFileBytes: MinFileBytes,
	}
	dom := map[string]*DomainStat{}
	catBytes := map[string]int{}
	catN := map[string]int{}
	for _, name := range Categories {
		catBytes[name] = 0
		catN[name] = 0
	}
	ensure := func(host string) *DomainStat {
		d, ok := dom[host]
		if !ok {
			d = &DomainStat{Host: host, Categories: map[string]int{}}
			for _, name := range Categories {
				d.Categories[name] = 0
			}
			dom[host] = d
		}
		return d
	}
	for _, flow := range cap.Flows {
		host := canonicalHost(flow.Host)
		cat := category(flow)
		d := ensure(host)
		d.Requests++
		d.BodyBytes += flow.BodyBytes
		d.ReqBytes += flow.ReqBytes
		d.Categories[cat] += flow.BodyBytes
		catBytes[cat] += flow.BodyBytes
		catN[cat]++
		rep.BodyBytes += flow.BodyBytes
		rep.ReqBytes += flow.ReqBytes
		rep.FlowCount++

		gitHits, inflated := inspectGit(flow)
		var secrets []match
		for _, m := range scanBytes(flow.Body) {
			m.source = "body"
			secrets = append(secrets, m)
		}
		for _, extra := range inflated {
			for _, m := range scanBytes(extra.data) {
				m.source = "git_object"
				m.object = extra.name
				secrets = append(secrets, m)
			}
		}
		secrets = dedupeSecrets(secrets)
		for _, m := range secrets {
			rep.Secrets = append(rep.Secrets, SecretHit{
				Pattern:  m.pattern,
				Host:     host,
				Path:     flow.Path,
				Redacted: redact(m.text),
				Source:   m.source,
				FlowID:   flow.ID,
				Object:   m.object,
			})
			d.SecretCount++
		}
		for _, f := range files {
			if len(f.Data) < MinFileBytes {
				continue
			}
			if bytes.Contains(flow.Body, f.Data) {
				rep.Files = append(rep.Files, FileHit{
					Rel: f.Rel, Host: host, Path: flow.Path, SHA256: f.SHA,
					Size: f.Size, Source: "body", FlowID: flow.ID,
				})
				d.FileCount++
			}
			for _, extra := range inflated {
				if bytes.Contains(extra.data, f.Data) || bytes.Equal(extra.data, f.Data) {
					rep.Files = append(rep.Files, FileHit{
						Rel: f.Rel, Host: host, Path: flow.Path, SHA256: f.SHA,
						Size: f.Size, Source: "git_object", FlowID: flow.ID,
					})
					d.FileCount++
					break
				}
			}
		}
		for _, g := range gitHits {
			g.Host = host
			g.Path = flow.Path
			g.FlowID = flow.ID
			rep.Git = append(rep.Git, g)
			if g.Kind != "smart-http" {
				d.GitObjects++
			}
		}
	}
	inv := map[string]*Invisible{}
	var invOrder []string
	for _, item := range cap.Invisible {
		host := canonicalHost(item.Host)
		key := host + "\x00" + item.Reason
		got, ok := inv[key]
		if !ok {
			got = &Invisible{Host: host, Port: item.Port, Reason: item.Reason, Detail: item.Detail, Attempts: 0}
			inv[key] = got
			invOrder = append(invOrder, key)
		}
		got.Attempts++
	}
	for _, key := range invOrder {
		rep.Invisible = append(rep.Invisible, *inv[key])
	}
	var hosts []string
	for h := range dom {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		rep.Domains = append(rep.Domains, *dom[h])
	}
	for _, name := range Categories {
		rep.Categories = append(rep.Categories, CategoryStat{Name: name, BodyBytes: catBytes[name], Requests: catN[name]})
	}
	sort.Slice(rep.Secrets, func(i, j int) bool {
		a, b := rep.Secrets[i], rep.Secrets[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Pattern != b.Pattern {
			return a.Pattern < b.Pattern
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Object < b.Object
	})
	sort.Slice(rep.Files, func(i, j int) bool {
		if rep.Files[i].Host != rep.Files[j].Host {
			return rep.Files[i].Host < rep.Files[j].Host
		}
		if rep.Files[i].Rel != rep.Files[j].Rel {
			return rep.Files[i].Rel < rep.Files[j].Rel
		}
		return rep.Files[i].Source < rep.Files[j].Source
	})
	sort.Slice(rep.Git, func(i, j int) bool {
		if rep.Git[i].Host != rep.Git[j].Host {
			return rep.Git[i].Host < rep.Git[j].Host
		}
		if rep.Git[i].Object != rep.Git[j].Object {
			return rep.Git[i].Object < rep.Git[j].Object
		}
		return rep.Git[i].Kind < rep.Git[j].Kind
	})
	return rep
}

// BaitHosts returns hosts where pattern was found, in sorted order.
func BaitHosts(rep *Report, pattern string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range rep.Secrets {
		if s.Pattern == pattern && !seen[s.Host] {
			seen[s.Host] = true
			out = append(out, s.Host)
		}
	}
	sort.Strings(out)
	return out
}

type match struct {
	pattern  string
	start    int
	end      int
	text     string
	source   string
	object   string
	specific bool
}

type inflated struct {
	name string
	data []byte
}

func inspectGit(flow capture.Flow) ([]GitHit, []inflated) {
	var hits []GitHit
	var blobs []inflated
	ct := strings.ToLower(flow.ContentType)
	path := flow.Path
	smart := strings.Contains(path, "git-upload-pack") ||
		strings.Contains(path, "git-receive-pack") ||
		strings.HasSuffix(path, "/info/refs") ||
		strings.Contains(flow.Query, "service=git-") ||
		strings.Contains(ct, "git")
	pack, err := gitpack.Parse(flow.Body)
	if err == nil {
		for _, o := range pack.Objects {
			name := pack.Paths[o.Hash]
			hit := GitHit{
				Kind:   o.Type,
				Object: name,
				Hash:   o.Hash,
				Size:   len(o.Data),
				PackOK: pack.ChecksumOK,
			}
			hits = append(hits, hit)
			if o.Type == gitpack.TypeBlob || o.Type == gitpack.TypeCommit {
				label := name
				if label == "" {
					label = o.Type
				}
				blobs = append(blobs, inflated{name: label, data: o.Data})
			}
		}
		return hits, blobs
	}
	if smart {
		hits = append(hits, GitHit{Kind: "smart-http", Size: flow.BodyBytes})
	}
	return hits, nil
}

func category(flow capture.Flow) string {
	if isGit(flow) {
		return "git"
	}
	host := strings.ToLower(flow.Host)
	path := strings.ToLower(flow.Path)
	ct := strings.ToLower(flow.ContentType)
	if strings.Contains(host, "telemetry") || strings.Contains(host, "analytics") ||
		strings.Contains(path, "/telemetry") || strings.Contains(path, "/events") ||
		strings.Contains(path, "/analytics") || strings.Contains(path, "/v1/traces") {
		return "telemetry"
	}
	if strings.Contains(path, "/v1/messages") || strings.Contains(path, "/chat/completions") ||
		strings.Contains(path, "/v1/responses") || strings.Contains(path, "/v1/completions") {
		return "inference"
	}
	if strings.Contains(ct, "multipart/") || strings.Contains(path, "/upload") ||
		strings.Contains(path, "/sync") || strings.Contains(path, "/files") {
		return "upload"
	}
	if strings.Contains(ct, "json") || strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/api/") {
		return "api"
	}
	return "other"
}

func isGit(flow capture.Flow) bool {
	ct := strings.ToLower(flow.ContentType)
	path := flow.Path
	if strings.Contains(path, "git-upload-pack") || strings.Contains(path, "git-receive-pack") ||
		strings.HasSuffix(path, "/info/refs") || strings.Contains(flow.Query, "service=git-") ||
		strings.Contains(ct, "application/x-git") {
		return true
	}
	if _, err := gitpack.Parse(flow.Body); err == nil {
		return true
	}
	return false
}

type pattern struct {
	name     string
	re       *regexp.Regexp
	specific bool
	group    int // 0 = full match, 1 = first submatch
}

var patterns = []pattern{
	{name: "bait", re: regexp.MustCompile(`EL_BAIT_[A-Za-z0-9_-]{8,}`), specific: true},
	{name: "aws_access_key", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), specific: true},
	{name: "github_pat", re: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), specific: true},
	{name: "github_fine_grained", re: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`), specific: true},
	{name: "slack_token", re: regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), specific: true},
	{name: "pem_private_key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), specific: true},
	{name: "sk_token", re: regexp.MustCompile(`sk-(?:live-|test-|proj-)?[A-Za-z0-9_-]{20,}`), specific: true},
	{name: "generic_assignment", re: regexp.MustCompile(`(?i)(?:api[_-]?key|secret|access[_-]?token|password)\s*[:=]\s*['"]?([A-Za-z0-9+/_=.-]{20,})`), specific: false, group: 1},
}

func scanBytes(b []byte) []match {
	if len(b) == 0 {
		return nil
	}
	var found []match
	for _, p := range patterns {
		idx := p.re.FindAllSubmatchIndex(b, -1)
		for _, loc := range idx {
			start, end := loc[0], loc[1]
			if p.group == 1 && len(loc) >= 4 && loc[2] >= 0 {
				start, end = loc[2], loc[3]
			}
			if start < 0 || end > len(b) || start >= end {
				continue
			}
			found = append(found, match{
				pattern:  p.name,
				start:    start,
				end:      end,
				text:     string(b[start:end]),
				specific: p.specific,
			})
		}
	}
	return resolveOverlaps(found)
}

func resolveOverlaps(in []match) []match {
	var specific []match
	for _, m := range in {
		if m.specific {
			specific = append(specific, m)
		}
	}
	var kept []match
	for _, m := range in {
		if !m.specific {
			drop := false
			for _, s := range specific {
				if overlaps(m, s) {
					drop = true
					break
				}
			}
			if drop {
				continue
			}
		}
		kept = append(kept, m)
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].start != kept[j].start {
			return kept[i].start < kept[j].start
		}
		return (kept[i].end - kept[i].start) > (kept[j].end - kept[j].start)
	})
	var out []match
	for _, m := range kept {
		contained := false
		for _, o := range out {
			if m.start >= o.start && m.end <= o.end {
				contained = true
				break
			}
		}
		if !contained {
			out = append(out, m)
		}
	}
	return out
}

func overlaps(a, b match) bool {
	return a.start < b.end && b.start < a.end
}

func dedupeSecrets(in []match) []match {
	seen := map[string]bool{}
	var out []match
	for _, m := range in {
		key := m.pattern + "\x00" + m.source + "\x00" + m.object + "\x00" + m.text
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out
}

func redact(s string) string {
	if strings.HasPrefix(s, "-----BEGIN ") {
		return s
	}
	r := []rune(s)
	if len(r) <= 8 {
		return "***"
	}
	return string(r[:4]) + "…" + string(r[len(r)-2:])
}

func canonicalHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

// PatternNames is the detector's pattern list, in report order.
func PatternNames() []string {
	out := make([]string, len(patterns))
	for i, p := range patterns {
		out[i] = p.name
	}
	return out
}

// DetectPatterns returns the pattern set found in b.
func DetectPatterns(b []byte) []string {
	ms := scanBytes(b)
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		if !seen[m.pattern] {
			seen[m.pattern] = true
			out = append(out, m.pattern)
		}
	}
	sort.Strings(out)
	return out
}
