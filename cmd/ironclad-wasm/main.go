//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/mevlanayalcin/ironclad/pkg/analyzer"
)

func analyzeJS(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return `{"error":"expected (target, chainId, filesJSON)"}`
	}
	target := args[0].String()
	chainID := args[1].String()
	filesJSON := args[2].String()
	var files map[string]string
	if err := json.Unmarshal([]byte(filesJSON), &files); err != nil {
		return `{"error":"invalid files json"}`
	}
	rep := analyzer.AnalyzeSources(target, files)
	digest := analyzer.AttestationDigest(chainID, rep.Target, rep.SourceHash, rep.ReportDigest, rep.AnalyzerVersion, rep.Counts)
	out, _ := json.Marshal(map[string]any{
		"report":            rep,
		"attestationDigest": digest,
	})
	return string(out)
}

func main() {
	js.Global().Set("ironcladAnalyzeWASM", js.FuncOf(analyzeJS))
	select {}
}
