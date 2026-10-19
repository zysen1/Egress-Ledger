package classify

import (
	"bytes"
	"sort"
	"strings"
)

// FixtureDataset is the labeled set used for detector measurements.
const FixtureDataset = "ledger-fixture-v1"

// Metrics are case-level scores. A case is exact when the detected set
// equals the labeled set. Precision and recall use that exact-match rule:
// a mismatched positive counts as both a false positive and a false negative.
type Metrics struct {
	Dataset         string   `json:"dataset"`
	SecretCases     int      `json:"secret_cases"`
	SecretExact     int      `json:"secret_exact"`
	SecretTP        int      `json:"secret_tp"`
	SecretFP        int      `json:"secret_fp"`
	SecretFN        int      `json:"secret_fn"`
	SecretPrecision float64  `json:"secret_precision"`
	SecretRecall    float64  `json:"secret_recall"`
	GitCases        int      `json:"git_cases"`
	GitExact        int      `json:"git_exact"`
	GitAccuracy     float64  `json:"git_accuracy"`
	FileCases       int      `json:"file_cases"`
	FileExact       int      `json:"file_exact"`
	FileAccuracy    float64  `json:"file_accuracy"`
	Failures        []string `json:"failures,omitempty"`
}

type secretCase struct {
	name string
	body string
	want []string
}

type gitCase struct {
	name    string
	flow    func() (string, string, string, []byte) // path, query, contentType, body
	wantGit bool
	wantN   int
}

type fileCase struct {
	name  string
	files map[string]string
	body  string
	want  []string
}

// EvaluateFixture scores the built-in labeled fixture.
func EvaluateFixture() Metrics {
	var m Metrics
	m.Dataset = FixtureDataset
	var failures []string
	for _, c := range secretCorpus() {
		m.SecretCases++
		got := DetectPatterns([]byte(c.body))
		if stringSetEqual(got, c.want) {
			m.SecretExact++
			if len(c.want) > 0 {
				m.SecretTP++
			}
			continue
		}
		failures = append(failures, "secret "+c.name+": got "+strings.Join(got, ",")+" want "+strings.Join(c.want, ","))
		if len(got) > 0 {
			m.SecretFP++
		}
		if len(c.want) > 0 {
			m.SecretFN++
		}
	}
	m.SecretPrecision = ratio(m.SecretTP, m.SecretTP+m.SecretFP)
	m.SecretRecall = ratio(m.SecretTP, m.SecretTP+m.SecretFN)

	for _, c := range gitCorpus() {
		m.GitCases++
		path, query, ct, body := c.flow()
		flow := fakeFlow(path, query, ct, body)
		hits, _ := inspectGit(flow)
		objects := 0
		for _, h := range hits {
			if h.Kind != "smart-http" {
				objects++
			}
		}
		isGit := category(flow) == "git"
		if isGit == c.wantGit && objects == c.wantN {
			m.GitExact++
			continue
		}
		failures = append(failures, "git "+c.name)
	}
	m.GitAccuracy = ratio(m.GitExact, m.GitCases)

	for _, c := range fileCorpus() {
		m.FileCases++
		var files []File
		for rel, content := range c.files {
			files = append(files, File{Rel: rel, Size: len(content), Data: []byte(content), SHA: rel})
		}
		got := matchFiles(files, []byte(c.body))
		if stringSetEqual(got, c.want) {
			m.FileExact++
			continue
		}
		failures = append(failures, "file "+c.name+": got "+strings.Join(got, ",")+" want "+strings.Join(c.want, ","))
	}
	m.FileAccuracy = ratio(m.FileExact, m.FileCases)
	sort.Strings(failures)
	m.Failures = failures
	return m
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

func stringSetEqual(a, b []string) bool {
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func matchFiles(files []File, body []byte) []string {
	var got []string
	for _, f := range files {
		if len(f.Data) < MinFileBytes {
			continue
		}
		if bytes.Contains(body, f.Data) {
			got = append(got, f.Rel)
		}
	}
	sort.Strings(got)
	return got
}

func secretCorpus() []secretCase {
	pem := "-----BEGIN PRIVATE KEY-----\nMIIE-not-a-real-key\n-----END PRIVATE KEY-----"
	return []secretCase{
		{name: "bait_env", body: "OPENAI_API_KEY=EL_BAIT_sk-live-egressledger-7f3a9c2e1b\n", want: []string{"bait"}},
		{name: "bait_json", body: `{"note":"EL_BAIT_demo-token-aabbccdd"}`, want: []string{"bait"}},
		{name: "aws", body: "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n", want: []string{"aws_access_key"}},
		{name: "aws_in_log", body: "upload failed key AKIAIOSFODNN7EXAMPLE at 12:00", want: []string{"aws_access_key"}},
		{name: "github", body: "token ghp_abcdefghijklmnopqrstuvwxyz0123456789", want: []string{"github_pat"}},
		{name: "github_fine", body: "github_pat_11AAAAAAA0123456789_abcdefghijklmnopqrstuv", want: []string{"github_fine_grained"}},
		{name: "slack", body: "xoxb-123456789012-abcdefghij", want: []string{"slack_token"}},
		{name: "pem", body: pem, want: []string{"pem_private_key"}},
		{name: "sk", body: "Authorization: Bearer sk-live-egressledger-7f3a9c2e1b", want: []string{"sk_token"}},
		{name: "generic", body: "api_key=abcdEFGH1234567890zzzz", want: []string{"generic_assignment"}},
		{name: "generic_password", body: `password="correct-horse-battery-9"`, want: []string{"generic_assignment"}},
		{name: "prose", body: "the secret is not in this sentence", want: nil},
		{name: "short_password", body: "password: hunter2", want: nil},
		{name: "env_ref", body: "api_key=${API_KEY}", want: nil},
		{name: "public_key", body: "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----", want: nil},
		{name: "code_token", body: "token := os.Getenv(\"TOKEN\")", want: nil},
		{name: "checksum", body: "checksum=0123456789abcdef0123456789abcdef", want: nil},
		{name: "sk_short", body: "sk-short", want: nil},
		{name: "akia_short", body: "AKIAEXAMPLE", want: nil},
		{name: "placeholder", body: "api_key=YOUR_API_KEY_HERE", want: nil},
	}
}

func gitCorpus() []gitCase {
	blob := []byte("blob-body-for-the-git-fixture-which-is-long-enough")
	obj := gitObject(gitpackTypeBlob(), blob)
	pack := mustPack([]gitObj{obj})
	two := mustPack([]gitObj{gitObject(gitpackTypeBlob(), []byte("one-one-one-one-one")), gitObject(gitpackTypeBlob(), []byte("two-two-two-two-two"))})
	return []gitCase{
		{name: "pack_one", flow: func() (string, string, string, []byte) {
			return "/git-upload-pack", "", "application/x-git-upload-pack-result", pack
		}, wantGit: true, wantN: 1},
		{name: "pack_two", flow: func() (string, string, string, []byte) {
			return "/git-upload-pack", "", "application/x-git-upload-pack-result", two
		}, wantGit: true, wantN: 2},
		{name: "smart_no_body", flow: func() (string, string, string, []byte) {
			return "/repo.git/git-upload-pack", "", "application/x-git-upload-pack-request", nil
		}, wantGit: true, wantN: 0},
		{name: "info_refs", flow: func() (string, string, string, []byte) {
			return "/repo.git/info/refs", "service=git-upload-pack", "", nil
		}, wantGit: true, wantN: 0},
		{name: "json", flow: func() (string, string, string, []byte) {
			return "/v1/messages", "", "application/json", []byte(`{"role":"user"}`)
		}, wantGit: false, wantN: 0},
		{name: "package_word", flow: func() (string, string, string, []byte) {
			return "/v1/notes", "", "text/plain", []byte("PACKAGE is a word, not a pack header")
		}, wantGit: false, wantN: 0},
	}
}

func fileCorpus() []fileCase {
	long := strings.Repeat("runbook line.\n", 6)
	return []fileCase{
		{name: "equal", files: map[string]string{"a.txt": long}, body: long, want: []string{"a.txt"}},
		{name: "embedded", files: map[string]string{"a.txt": long}, body: "prefix\n" + long + "\nsuffix", want: []string{"a.txt"}},
		{name: "half", files: map[string]string{"a.txt": long}, body: long[:len(long)/2], want: nil},
		{name: "tiny", files: map[string]string{"tiny.txt": "ok\n"}, body: "ok\n", want: nil},
		{name: "other_file", files: map[string]string{"a.txt": long, "b.txt": strings.Repeat("other file.\n", 6)}, body: long, want: []string{"a.txt"}},
	}
}
