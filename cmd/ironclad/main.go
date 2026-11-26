// Command ironclad is a fast Gno.land smart-contract static security analyzer
// supporting local directories, live remote chain scanning (vm/qfile), JSON,
// SARIF v2.1.0, Markdown output, and onyx-1 attestation command generation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mevlanayalcin/ironclad/pkg/analyzer"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: ironclad <scan|rules> [flags] <dir-or-pkgpath>")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "rules":
		for _, m := range analyzer.SortedRuleMetas() {
			fmt.Printf("%-10s %-8s %-20s %s\n", m.ID, m.Severity, m.ThreatClass, m.Title)
		}
	case "scan":
		runScan(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "Unknown subcommand:", os.Args[1])
		os.Exit(1)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	remote := fs.String("remote", "", "Gno RPC URL for live remote package scanning via vm/qfile (e.g. https://rpc.onyx.testnets.gno.land:443)")
	format := fs.String("format", "text", "Output format: text | json | sarif | markdown")
	targetLabel := fs.String("pkg", "", "Canonical package path label (e.g. gno.land/r/<addr>/app)")
	chainID := fs.String("chain-id", "onyx-1", "Chain ID for attestation digest calculation")
	attestRealm := fs.String("attest-realm", "", "Optional Ironclad realm path to print gnokey PublishAttestation command")
	failOnHigh := fs.Bool("fail-on-high", false, "Exit with code 2 if any CRITICAL or HIGH findings exist")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Missing target directory or remote package path")
		os.Exit(1)
	}
	target := fs.Arg(0)

	var rep analyzer.Report
	var err error
	if *remote != "" {
		files, ferr := analyzer.FetchRemotePackage(context.Background(), *remote, target)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "remote fetch failed: %v\n", ferr)
			os.Exit(1)
		}
		rep = analyzer.AnalyzeSources(target, files)
	} else {
		label := *targetLabel
		if label == "" {
			label = target
		}
		rep, err = analyzer.AnalyzeDirectory(target, label)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
			os.Exit(1)
		}
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	case "sarif":
		b, _ := analyzer.ToSARIF(rep)
		fmt.Println(string(b))
	case "markdown":
		fmt.Print(analyzer.ToMarkdown(rep))
	default:
		fmt.Printf("Ironclad %s | Target: %s\n", rep.AnalyzerVersion, rep.Target)
		fmt.Printf("Grade: %s (%d/100) | Files: %d | C:%d H:%d M:%d L:%d I:%d\n",
			rep.Grade, rep.Score, rep.FilesScanned,
			rep.Counts.Critical, rep.Counts.High, rep.Counts.Medium, rep.Counts.Low, rep.Counts.Info)
		fmt.Printf("Source SHA-256 : %s\n", rep.SourceHash)
		fmt.Printf("Report Digest  : %s\n", rep.ReportDigest)
		digest := analyzer.AttestationDigest(*chainID, rep.Target, rep.SourceHash, rep.ReportDigest, rep.AnalyzerVersion, rep.Counts)
		fmt.Printf("Attest Digest  : %s (chain=%s)\n", digest, *chainID)
		if len(rep.Findings) == 0 {
			fmt.Println("Status         : PASS (0 security findings)")
		} else {
			fmt.Println("\nFindings:")
			for _, f := range rep.Findings {
				fmt.Printf("  [%s] %s (%s) %s:%d — %s\n      Fix: %s\n",
					f.Severity, f.RuleID, f.ThreatClass, f.File, f.Line, f.Message, f.Remediation)
			}
		}
		if *attestRealm != "" {
			fmt.Printf("\nPublish on-chain attestation command:\n  gnokey maketx call <key> -broadcast -chainid %s -pkgpath %s -func PublishAttestation \\\n"+
				"    -args %q -args %q -args %q -args %q -args %d -args %d -args %d -args %d -args %d -args %q -args %q -args %q\n",
				*chainID, *attestRealm, rep.Target, rep.SourceHash, rep.ReportDigest, rep.AnalyzerVersion,
				rep.Counts.Critical, rep.Counts.High, rep.Counts.Medium, rep.Counts.Low, rep.Counts.Info,
				strings.Join(rep.RulesTriggered, ","),
				fmt.Sprintf("Ironclad static audit: grade %s (%d/100)", rep.Grade, rep.Score),
				"https://github.com/mevlanayalcin/ironclad",
			)
		}
	}

	if *failOnHigh && (rep.Counts.Critical > 0 || rep.Counts.High > 0) {
		os.Exit(2)
	}
}
