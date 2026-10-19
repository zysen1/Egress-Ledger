// Command egress-ledger records what a coding agent sends off the machine
// and prints a per-version transparency report.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zysen1/Egress-Ledger/internal/ca"
	"github.com/zysen1/Egress-Ledger/internal/capture"
	"github.com/zysen1/Egress-Ledger/internal/classify"
	"github.com/zysen1/Egress-Ledger/internal/demo"
	"github.com/zysen1/Egress-Ledger/internal/proxy"
	"github.com/zysen1/Egress-Ledger/internal/report"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "ca":
		err = cmdCA(os.Args[2:])
	case "proxy":
		err = cmdProxy(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "demo":
		err = cmdDemo(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `egress-ledger — transparency report for coding-agent egress

Not a firewall. pipelock blocks traffic; this records it and diffs versions.

  egress-ledger ca init --out DIR
  egress-ledger proxy --listen 127.0.0.1:8080 --ca DIR --capture FILE --agent NAME --version VER
  egress-ledger report --capture FILE --workspace DIR --out report.html
  egress-ledger diff --old OLD.jsonl --new NEW.jsonl --workspace DIR --out diff.html
  egress-ledger demo --out DIR

The offline demo needs no API key and no real agent.
`)
}

func cmdCA(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return fmt.Errorf("usage: egress-ledger ca init --out DIR")
	}
	fs := flag.NewFlagSet("ca init", flag.ContinueOnError)
	out := fs.String("out", "", "directory for ca.crt and ca.key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("ca init: --out is required")
	}
	a, err := ca.Generate(*out)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\ntrust this CA in the agent process (SSL_CERT_FILE or the language trust store)\n", a.Dir)
	return nil
}

func cmdProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "proxy listen address")
	caDir := fs.String("ca", "", "CA directory from `ca init`")
	capPath := fs.String("capture", "capture.jsonl", "JSONL capture path")
	agent := fs.String("agent", "agent", "agent name recorded on each flow")
	version := fs.String("version", "", "agent version recorded on each flow")
	var maps stringList
	fs.Var(&maps, "map", "host:port=127.0.0.1:port (repeatable, plain HTTP upstream)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caDir == "" || *version == "" {
		return fmt.Errorf("proxy: --ca and --version are required")
	}
	authority, err := ca.Load(*caDir)
	if err != nil {
		return err
	}
	w, err := capture.Create(*capPath, *agent, *version)
	if err != nil {
		return err
	}
	defer w.Close()
	p := &proxy.Proxy{
		CA: authority, Agent: *agent, Version: *version,
		Map: maps.m, Capture: w,
	}
	if err := p.Start(*listen); err != nil {
		return err
	}
	defer p.Close()
	fmt.Printf("proxy %s\nca %s\ncapture %s\nagent %s %s\n", p.Addr(), *caDir, *capPath, *agent, *version)
	fmt.Println("trust the CA, then point the agent at this HTTP proxy. Ctrl-C stops the capture.")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("stopped")
	return nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	capPath := fs.String("capture", "", "JSONL capture")
	workspace := fs.String("workspace", "", "workspace used to detect full file contents")
	out := fs.String("out", "", "HTML report path")
	js := fs.String("json", "", "optional JSON report path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *capPath == "" || *workspace == "" || *out == "" {
		return fmt.Errorf("report: --capture, --workspace, and --out are required")
	}
	rep, err := loadReport(*capPath, *workspace)
	if err != nil {
		return err
	}
	page := report.PageFromReports(nil, rep, nil,
		fmt.Sprintf("agent %s · version %s · generated %s", rep.Agent, rep.Version, rep.Generated.Format(time.RFC3339)),
		[]string{fmt.Sprintf("%s %s sent %d body bytes across %d domains.", rep.Agent, rep.Version, rep.BodyBytes, len(rep.Domains))},
	)
	return writePage(*out, *js, page, rep)
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	oldPath := fs.String("old", "", "older JSONL capture")
	newPath := fs.String("new", "", "newer JSONL capture")
	workspace := fs.String("workspace", "", "workspace used to detect full file contents")
	out := fs.String("out", "", "HTML report path")
	js := fs.String("json", "", "optional JSON report path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *oldPath == "" || *newPath == "" || *workspace == "" || *out == "" {
		return fmt.Errorf("diff: --old, --new, --workspace, and --out are required")
	}
	oldRep, err := loadReport(*oldPath, *workspace)
	if err != nil {
		return err
	}
	newRep, err := loadReport(*newPath, *workspace)
	if err != nil {
		return err
	}
	diff := classify.Compare(oldRep, newRep)
	page := report.PageFromReports(oldRep, newRep, diff,
		fmt.Sprintf("%s %s → %s %s", oldRep.Agent, oldRep.Version, newRep.Agent, newRep.Version),
		[]string{fmt.Sprintf("Domains added: %s.", joinOrNone(diff.DomainsAdded)), fmt.Sprintf("Secret findings added: %d. Full files added: %d. Git objects added: %d.", len(diff.SecretsAdded), len(diff.FilesAdded), len(diff.GitAdded))},
	)
	payload := struct {
		Old  *classify.Report `json:"old"`
		New  *classify.Report `json:"new"`
		Diff *classify.Diff   `json:"diff"`
	}{oldRep, newRep, diff}
	return writePage(*out, *js, page, payload)
}

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	out := fs.String("out", "examples/demo-output", "directory for the capture, repo, and report")
	docs := fs.String("docs", "", "optional directory for demo-report.html and measured.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	summary, err := demo.Run(context.Background(), demo.Options{OutDir: *out, DocsDir: *docs})
	if err != nil {
		return err
	}
	fmt.Printf("dataset: %s\n", summary.Dataset)
	fmt.Printf("agent: %s (scripted, no API key)\n", summary.Agent)
	fmt.Printf("bait pattern %s observed at: %s\n", summary.BaitPattern, strings.Join(summary.BaitDomains, ", "))
	fmt.Printf("absent in: %s\n", summary.BaitAbsentIn)
	fmt.Printf("invisible: %s (%s)\n", strings.Join(summary.InvisibleHosts, ", "), summary.InvisibleReason)
	for _, v := range summary.Versions {
		fmt.Printf("%s flows=%d body_bytes=%d secrets=%d full_files=%d git_objects=%d invisible=%d\n",
			v.Version, v.Flows, v.BodyBytes, v.Secrets, v.FullFiles, v.GitObjects, v.Invisible)
		fmt.Printf("  categories: %s\n", formatCats(v.Categories))
	}
	fmt.Printf("fixture %s secret %d/%d exact, git %d/%d, files %d/%d\n",
		summary.Corpus.Dataset, summary.Corpus.SecretExact, summary.Corpus.SecretCases,
		summary.Corpus.GitExact, summary.Corpus.GitCases, summary.Corpus.FileExact, summary.Corpus.FileCases)
	fmt.Printf("wrote %s\n", *out)
	return nil
}

func loadReport(capPath, workspace string) (*classify.Report, error) {
	cap, err := capture.Load(capPath)
	if err != nil {
		return nil, err
	}
	files, err := classify.LoadWorkspace(workspace)
	if err != nil {
		return nil, err
	}
	return classify.Analyze(cap, files, time.Now().UTC()), nil
}

func writePage(htmlPath, jsonPath string, page report.Page, payload any) error {
	html, err := report.RenderHTML(page)
	if err != nil {
		return err
	}
	if err := os.WriteFile(htmlPath, html, 0o644); err != nil {
		return err
	}
	if jsonPath == "" {
		return nil
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(jsonPath, raw, 0o644)
}

func formatCats(m map[string]int) string {
	parts := make([]string, 0, len(classify.Categories))
	for _, name := range classify.Categories {
		parts = append(parts, fmt.Sprintf("%s=%d", name, m[name]))
	}
	return strings.Join(parts, " ")
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

type stringList struct {
	m map[string]string
}

func (s *stringList) String() string { return "" }

func (s *stringList) Set(v string) error {
	host, addr, ok := strings.Cut(v, "=")
	if !ok || host == "" || addr == "" {
		return fmt.Errorf("map %q: want host:port=addr", v)
	}
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[host] = addr
	return nil
}
