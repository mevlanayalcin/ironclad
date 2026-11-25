package analyzer

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ToSARIF serializes an Ironclad Report into SARIF v2.1.0 for GitHub Code Scanning.
func ToSARIF(rep Report) ([]byte, error) {
	rules := make([]map[string]any, 0, len(RuleCatalog))
	for _, m := range RuleCatalog {
		rules = append(rules, map[string]any{
			"id":               m.ID,
			"name":             m.ID,
			"shortDescription": map[string]string{"text": m.Title},
			"fullDescription":  map[string]string{"text": m.Remediation},
			"helpUri":          "https://github.com/gnolang/gno/blob/master/" + m.Reference,
			"properties":       map[string]any{"threatClass": m.ThreatClass, "severity": m.Severity},
		})
	}
	results := make([]map[string]any, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		level := "warning"
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			level = "error"
		} else if f.Severity == SeverityLow || f.Severity == SeverityInfo {
			level = "note"
		}
		results = append(results, map[string]any{
			"ruleId":  f.RuleID,
			"level":   level,
			"message": map[string]string{"text": f.Message + " Remediation: " + f.Remediation},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": f.File},
					"region":           map[string]int{"startLine": f.Line, "startColumn": f.Column},
				},
			}},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "Ironclad",
					"version":        rep.AnalyzerVersion,
					"informationUri": "https://github.com/mevlanayalcin/ironclad",
					"rules":          rules,
				},
			},
			"results": results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// ToMarkdown renders a concise audit summary report.
func ToMarkdown(rep Report) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Ironclad Security Report: `%s`\n\n", rep.Target))
	b.WriteString(fmt.Sprintf("- **Grade:** `%s` (**%d / 100**)\n", rep.Grade, rep.Score))
	b.WriteString(fmt.Sprintf("- **Analyzer:** `%s` (`%d` files scanned)\n", rep.AnalyzerVersion, rep.FilesScanned))
	b.WriteString(fmt.Sprintf("- **Source SHA-256:** `%s`\n", rep.SourceHash))
	b.WriteString(fmt.Sprintf("- **Report Digest:** `%s`\n", rep.ReportDigest))
	b.WriteString(fmt.Sprintf("- **Findings:** Critical `%d` · High `%d` · Medium `%d` · Low `%d` · Info `%d`\n\n",
		rep.Counts.Critical, rep.Counts.High, rep.Counts.Medium, rep.Counts.Low, rep.Counts.Info))
	if len(rep.Findings) == 0 {
		b.WriteString("Zero security findings detected across all 15 Gno Threat-Class & Lint rules.\n")
		return b.String()
	}
	b.WriteString("| Severity | Rule | Class | Location | Issue |\n|---|---|---|---|---|\n")
	for _, f := range rep.Findings {
		b.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s:%d` | %s |\n",
			f.Severity, f.RuleID, f.ThreatClass, f.File, f.Line, f.Message))
	}
	return b.String()
}
