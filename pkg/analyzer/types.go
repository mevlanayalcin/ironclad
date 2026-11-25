// Package analyzer implements a Go AST static security analyzer tailored for
// Gno.land smart contracts, enforcing all 5 official Threat Classes from
// docs/resources/gno-security.md, all 11 review checks from
// docs/resources/gno-ai-contract-review.md, and PR #5068 lint rules
// (AVL001, GLOBAL001, RENDER001).
package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

const (
	AnalyzerVersion   = "ironclad-1.0.0"
	ProtocolVersion   = "ironclad-v1"
	AttestationDomain = "ironclad-attestation-v1"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type RuleMeta struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	ThreatClass string   `json:"threatClass"`
	Severity    Severity `json:"severity"`
	Reference   string   `json:"reference"`
	Remediation string   `json:"remediation"`
}

type Finding struct {
	RuleID      string   `json:"ruleId"`
	ThreatClass string   `json:"threatClass"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Message     string   `json:"message"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Snippet     string   `json:"snippet,omitempty"`
	Remediation string   `json:"remediation"`
	Reference   string   `json:"reference"`
}

type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type Report struct {
	Target          string    `json:"target"`
	AnalyzerVersion string    `json:"analyzerVersion"`
	FilesScanned    int       `json:"filesScanned"`
	SourceHash      string    `json:"sourceHash"`
	ReportDigest    string    `json:"reportDigest"`
	Counts          Counts    `json:"counts"`
	Score           int       `json:"score"`
	Grade           string    `json:"grade"`
	RulesTriggered  []string  `json:"rulesTriggered"`
	Findings        []Finding `json:"findings"`
}

var RuleCatalog = map[string]RuleMeta{
	"GNO-TC1A": {
		ID:          "GNO-TC1A",
		Title:       "Interface method accepts cur realm (Class-1a cur-disclosure)",
		ThreatClass: "Class-1a",
		Severity:    SeverityCritical,
		Reference:   "docs/resources/gno-security.md#class-1a",
		Remediation: "Remove realm parameters from interfaces; accept caller address derived at the call site under cur.IsCurrent().",
	},
	"GNO-TC1B": {
		ID:          "GNO-TC1B",
		Title:       "Passing cur realm into untrusted interface or callback (Class-1b)",
		ThreatClass: "Class-1b",
		Severity:    SeverityHigh,
		Reference:   "docs/resources/gno-security.md#class-1b",
		Remediation: "Never pass live cur realm handles into interface methods or caller-supplied callbacks; derive caller address first.",
	},
	"GNO-TC2": {
		ID:          "GNO-TC2",
		Title:       "Caller-supplied identity parameter (Class-2 designation-forgery)",
		ThreatClass: "Class-2",
		Severity:    SeverityCritical,
		Reference:   "docs/resources/gno-security.md#class-2",
		Remediation: "Derive caller identity from cur.Previous().Address() under cur.IsCurrent(); do not trust caller/sender/owner address or pkgPath parameters.",
	},
	"GNO-TC3": {
		ID:          "GNO-TC3",
		Title:       "Unchecked open interface or bypassable interface sealing (Class-3)",
		ThreatClass: "Class-3",
		Severity:    SeverityHigh,
		Reference:   "docs/resources/gno-security.md#class-3",
		Remediation: "Enforce concrete type-switch or IsCanonical* allowlist checks at boundary functions; unexported marker methods are bypassable via embedding.",
	},
	"GNO-TC4": {
		ID:          "GNO-TC4",
		Title:       "Caller-supplied callback invoked with realm authority (Class-4)",
		ThreatClass: "Class-4",
		Severity:    SeverityHigh,
		Reference:   "docs/resources/gno-security.md#class-4",
		Remediation: "Avoid invoking caller-supplied func() callbacks under realm authority, or type callbacks with realm-owned private types.",
	},
	"GNO-SEC01": {
		ID:          "GNO-SEC01",
		Title:       "Missing cur.IsCurrent() guard in crossing function",
		ThreatClass: "Class-2",
		Severity:    SeverityCritical,
		Reference:   "docs/resources/gno-ai-contract-review.md#1",
		Remediation: "Call if !cur.IsCurrent() { panic(...) } (or a package-local guard helper) before reading cur.Previous() or mutating state.",
	},
	"GNO-SEC02": {
		ID:          "GNO-SEC02",
		Title:       "Unsafe payment guard (IsUser() or unguarded OriginSend)",
		ThreatClass: "Class-2",
		Severity:    SeverityCritical,
		Reference:   "docs/resources/gno-ai-contract-review.md#2",
		Remediation: "Guard OriginSend() payment handlers with cur.Previous().IsUserCall() (not IsUser(), which permits ephemeral MsgRun realms).",
	},
	"GNO-SEC03": {
		ID:          "GNO-SEC03",
		Title:       "Exported function returns pointer to mutable state or /p/ mutator",
		ThreatClass: "Write-Authority-Leak",
		Severity:    SeverityHigh,
		Reference:   "docs/resources/gno-ai-contract-review.md#3",
		Remediation: "Return value copies or scalar accessors instead of *avl.Tree, *bptree.Tree, or pointers to internal realm structs.",
	},
	"GNO-SEC04": {
		ID:          "GNO-SEC04",
		Title:       "Persisting realm or banker capability in package state",
		ThreatClass: "Capability-Persistence",
		Severity:    SeverityCritical,
		Reference:   "docs/resources/gno-ai-contract-review.md#6",
		Remediation: "Store address/pkgPath strings and mint banker.NewBanker(...) fresh inside each call; never store realm or banker.Banker in globals.",
	},
	"GNO-SEC05": {
		ID:          "GNO-SEC05",
		Title:       "Stack-walking chain/runtime/unsafe identity used alongside cur realm",
		ThreatClass: "Class-2",
		Severity:    SeverityHigh,
		Reference:   "docs/resources/gno-ai-contract-review.md#9",
		Remediation: "Replace unsafe.PreviousRealm(), unsafe.CurrentRealm(), and unsafe.OriginCaller() with cur.Previous() and cur.Address().",
	},
	"GNO-SEC06": {
		ID:          "GNO-SEC06",
		Title:       "Unsanitized Render(path) Markdown concatenation",
		ThreatClass: "Markdown-Injection",
		Severity:    SeverityMedium,
		Reference:   "docs/resources/gno-ai-contract-review.md#10",
		Remediation: "Import gno.land/p/nt/markdown/sanitize/v0 and wrap user/path strings with sanitize.InlineText, sanitize.TableCell, or sanitize.Block.",
	},
	"GNO-SEC07": {
		ID:          "GNO-SEC07",
		Title:       "Unbounded GetCoins() used for single-denom balance lookup",
		ThreatClass: "Gas-DoS",
		Severity:    SeverityMedium,
		Reference:   "docs/resources/gno-ai-contract-review.md#11",
		Remediation: "Use O(1) banker.GetCoin(addr, denom) instead of GetCoins(addr).AmountOf(denom) to prevent unsolicited-denom gas DoS.",
	},
	"AVL001": {
		ID:          "AVL001",
		Title:       "Unbounded avl.Tree iteration without offset/limit cap",
		ThreatClass: "Lint-DoS",
		Severity:    SeverityMedium,
		Reference:   "gnolang/gno#5068",
		Remediation: "Use IterateByOffset / ReverseIterateByOffset with a bounded page size instead of unbounded Iterate/ReverseIterate.",
	},
	"GLOBAL001": {
		ID:          "GLOBAL001",
		Title:       "Exported mutable global variable in realm",
		ThreatClass: "Lint-Encapsulation",
		Severity:    SeverityMedium,
		Reference:   "gnolang/gno#5068",
		Remediation: "Make package-level mutable variables unexported and expose safe value-copy getters.",
	},
	"RENDER001": {
		ID:          "RENDER001",
		Title:       "State mutation detected inside Render(path)",
		ThreatClass: "Lint-Purity",
		Severity:    SeverityMedium,
		Reference:   "gnolang/gno#5068",
		Remediation: "Keep Render(path string) strictly read-only; remove assignments or store mutations.",
	},
}

func ComputeScore(c Counts) int {
	penalty := c.Critical*30 + c.High*15 + c.Medium*6 + c.Low*2
	if penalty >= 100 {
		return 0
	}
	return 100 - penalty
}

func ComputeGrade(score int, c Counts) string {
	switch {
	case score == 100 && c.Critical == 0 && c.High == 0:
		return "A+"
	case score >= 90 && c.Critical == 0 && c.High == 0:
		return "A"
	case score >= 80 && c.Critical == 0:
		return "B"
	case score >= 65 && c.Critical == 0:
		return "C"
	case score >= 45:
		return "D"
	default:
		return "F"
	}
}

func appendLP(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
	b.WriteByte('|')
}

// AttestationDigest matches gno.land/p/<deployer>/ironclad.AttestationDigest byte-for-byte.
func AttestationDigest(
	chainID, targetPkgPath, sourceHash, reportDigest, analyzerVersion string,
	c Counts,
) string {
	var b strings.Builder
	b.WriteString(AttestationDomain)
	b.WriteByte('|')
	appendLP(&b, chainID)
	appendLP(&b, targetPkgPath)
	appendLP(&b, sourceHash)
	appendLP(&b, reportDigest)
	appendLP(&b, analyzerVersion)
	b.WriteString(strconv.Itoa(c.Critical))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(c.High))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(c.Medium))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(c.Low))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(c.Info))
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// HashSources computes a deterministic SHA-256 over sorted (filename, content) pairs.
func HashSources(files map[string]string) string {
	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		h.Write([]byte(strconv.Itoa(len(name)) + ":" + name + "|"))
		content := files[name]
		h.Write([]byte(strconv.Itoa(len(content)) + ":" + content + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func HashFindings(findings []Finding) string {
	raw, _ := json.Marshal(findings)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
