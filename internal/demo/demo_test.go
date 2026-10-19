package demo

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zysen1/Egress-Ledger/internal/gitpack"
)

func TestPackAcceptedByGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	files, err := materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := Pack(files)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(pack, []byte(BaitValue)) {
		t.Fatal("plaintext bait survived inside the compressed pack")
	}
	parsed, err := gitpack.Parse(pack)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.ChecksumOK {
		t.Fatal("checksum")
	}
	dir := t.TempDir()
	init := exec.Command("git", "init", "-b", "main")
	init.Dir = dir
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("init: %v %s", err, out)
	}
	unpack := exec.Command("git", "unpack-objects")
	unpack.Dir = dir
	unpack.Stdin = bytes.NewReader(pack)
	if out, err := unpack.CombinedOutput(); err != nil {
		t.Fatalf("unpack: %v %s", err, out)
	}
	var envHash string
	for _, obj := range parsed.Objects {
		if parsed.Paths[obj.Hash] == ".env" {
			envHash = obj.Hash
		}
	}
	if envHash == "" {
		t.Fatal("pack has no .env blob")
	}
	out, err := exec.Command("git", "-C", dir, "cat-file", "-p", envHash).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(BaitValue)) {
		t.Fatalf("git cat-file lost the bait: %s", out)
	}
}

func TestDemoNamesBaitDomain(t *testing.T) {
	dir := t.TempDir()
	summary, err := Run(context.Background(), Options{OutDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	wantDomains := []string{hostGit, hostUpload}
	if !slices.Equal(summary.BaitDomains, wantDomains) {
		t.Fatalf("bait domains %v", summary.BaitDomains)
	}
	if summary.BaitAbsentIn != oldVersion {
		t.Fatalf("absent %s", summary.BaitAbsentIn)
	}
	if !slices.Equal(summary.InvisibleHosts, []string{hostPinned}) || summary.InvisibleReason != "cert_pin_or_tls_reject" {
		t.Fatalf("invisible %+v", summary)
	}
	if summary.TinyFileReportedAsFull {
		t.Fatal("tiny file counted as a full file")
	}
	if !slices.Equal(summary.DiffDomainsAdded, wantDomains) {
		t.Fatalf("diff domains %v", summary.DiffDomainsAdded)
	}
	if len(summary.Versions) != 2 {
		t.Fatal(summary.Versions)
	}
	v1, v2 := summary.Versions[0], summary.Versions[1]
	if v1.Version != oldVersion || v1.Secrets != 0 || v1.FullFiles != 0 || v1.GitObjects != 0 || v1.Invisible != 0 || v1.Flows != 2 {
		t.Fatalf("v1 %+v", v1)
	}
	if v1.Categories["inference"] <= 0 || v1.Categories["telemetry"] <= 0 || v1.Categories["upload"] != 0 || v1.Categories["git"] != 0 {
		t.Fatalf("v1 categories %+v", v1.Categories)
	}
	if v2.Version != newVersion || v2.Secrets != 2 || v2.Flows != 4 || v2.Invisible != 1 || v2.GitObjects != 7 || v2.FullFiles != 5 {
		t.Fatalf("v2 %+v", v2)
	}
	if v2.Categories["upload"] <= 0 || v2.Categories["git"] <= 0 {
		t.Fatalf("v2 categories %+v", v2.Categories)
	}
	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	for _, needle := range []string{hostGit, hostUpload, hostPinned, "cert_pin_or_tls_reject", "not a firewall", "bait", oldVersion, newVersion} {
		if !strings.Contains(text, needle) {
			t.Fatalf("report missing %q", needle)
		}
	}
	if strings.Contains(text, BaitValue) {
		t.Fatal("html contains the raw bait")
	}
	if summary.Corpus.SecretExact != summary.Corpus.SecretCases || summary.Corpus.Failures != nil {
		t.Fatalf("corpus %+v", summary.Corpus)
	}
	info, err := os.Stat(filepath.Join(dir, "bait-repo", ".git"))
	if err != nil || !info.IsDir() {
		t.Fatal("bait repo was not committed")
	}
}
