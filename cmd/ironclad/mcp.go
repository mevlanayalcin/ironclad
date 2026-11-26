package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mevlanayalcin/ironclad/pkg/analyzer"
)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *mcpError `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpConfig struct {
	RPC     string
	Realm   string
	ChainID string
}

func runMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	rpcURL := fs.String("remote", "https://rpc.onyx.testnets.gno.land:443", "Default Gno RPC URL for remote vm/qfile and attestation queries")
	realm := fs.String("realm", "gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad", "Default Ironclad attestation registry realm path")
	chainID := fs.String("chain-id", "onyx-1", "Default Gno chain ID for attestation digest calculation")
	_ = fs.Parse(args)

	serveMCP(context.Background(), os.Stdin, os.Stdout, mcpConfig{
		RPC:     *rpcURL,
		Realm:   *realm,
		ChainID: *chainID,
	})
}

func serveMCP(ctx context.Context, r io.Reader, w io.Writer, cfg mcpConfig) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(w)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req mcpRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(mcpResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &mcpError{Code: -32700, Message: "parse error: " + err.Error()},
			})
			continue
		}
		// JSON-RPC 2.0 notifications omit "id" and MUST NOT emit a response.
		if req.ID == nil {
			continue
		}
		resp := handleMCPRequest(ctx, req, cfg)
		_ = enc.Encode(resp)
	}
}

func handleMCPRequest(ctx context.Context, req mcpRequest, cfg mcpConfig) mcpResponse {
	switch req.Method {
	case "initialize":
		return mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{
					"name":    "ironclad-mcp",
					"version": analyzer.AnalyzerVersion,
				},
			},
		}
	case "ping":
		return mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}
	case "tools/list":
		return mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": []map[string]any{
					{
						"name":        "ironclad_scan_source",
						"description": "Run Ironclad 15-rule Gno AST static security analyzer (+ PARSE-ERR) on raw .gno source code and compute canonical SHA-256 report and attestation digests.",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"source":   map[string]any{"type": "string", "description": "Gno contract source code (.gno)"},
								"filename": map[string]any{"type": "string", "description": "Virtual filename (default: contract.gno)"},
								"target":   map[string]any{"type": "string", "description": "Canonical package path label (default: gno.land/r/sandbox/contract)"},
								"chainId":  map[string]any{"type": "string", "description": "Chain ID for AttestationDigest (default: onyx-1)"},
							},
							"required": []string{"source"},
						},
					},
					{
						"name":        "ironclad_scan_remote",
						"description": "Fetch live .gno source files from a deployed Gno.land package/realm via ABCI vm/qfile and run full deterministic Ironclad AST security analysis.",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"pkgPath": map[string]any{"type": "string", "description": "Live Gno package/realm path (e.g. gno.land/r/gnoland/blog)"},
								"rpcUrl":  map[string]any{"type": "string", "description": "Optional Gno RPC URL override"},
								"chainId": map[string]any{"type": "string", "description": "Optional chain ID override (default: onyx-1)"},
							},
							"required": []string{"pkgPath"},
						},
					},
					{
						"name":        "ironclad_verify_attestation",
						"description": "Trustlessly verify an on-chain Ironclad attestation by querying r/.../ironclad json/pkg/<pkgPath>, independently fetching live chain source via vm/qfile, re-running deterministic AST analysis, and checking byte-for-byte SHA-256 digest equality.",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"pkgPath":       map[string]any{"type": "string", "description": "Live Gno package/realm path to verify"},
								"rpcUrl":        map[string]any{"type": "string", "description": "Optional Gno RPC URL override"},
								"ironcladRealm": map[string]any{"type": "string", "description": "Optional Ironclad registry realm override"},
								"chainId":       map[string]any{"type": "string", "description": "Optional chain ID override (default: onyx-1)"},
							},
							"required": []string{"pkgPath"},
						},
					},
					{
						"name":        "ironclad_list_rules",
						"description": "List all 15 Gno Threat-Class Taxonomy AST security & lint rules (+ PARSE-ERR) enforced by Ironclad.",
						"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
					},
				},
			},
		}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return mcpResponse{JSONRPC: "2.0", ID: req.ID, Error: &mcpError{Code: -32602, Message: "invalid params: " + err.Error()}}
		}
		out, isErr := executeMCPTool(ctx, p.Name, p.Arguments, cfg)
		raw, _ := json.Marshal(out)
		return mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{{"type": "text", "text": string(raw)}},
				"isError": isErr,
			},
		}
	default:
		return mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpError{Code: -32601, Message: "method not found: " + req.Method},
		}
	}
}

func executeMCPTool(ctx context.Context, name string, rawArgs json.RawMessage, cfg mcpConfig) (any, bool) {
	switch name {
	case "ironclad_list_rules":
		return map[string]any{
			"analyzerVersion": analyzer.AnalyzerVersion,
			"rules":           analyzer.SortedRuleMetas(),
		}, false

	case "ironclad_scan_source":
		var a struct {
			Source   string `json:"source"`
			Filename string `json:"filename"`
			Target   string `json:"target"`
			ChainID  string `json:"chainId"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil || strings.TrimSpace(a.Source) == "" {
			return map[string]any{"error": "source is required"}, true
		}
		if a.Filename == "" {
			a.Filename = "contract.gno"
		}
		if a.Target == "" {
			a.Target = "gno.land/r/sandbox/contract"
		}
		if a.ChainID == "" {
			a.ChainID = cfg.ChainID
		}
		rep := analyzer.AnalyzeSources(a.Target, map[string]string{a.Filename: a.Source})
		digest := analyzer.AttestationDigest(a.ChainID, rep.Target, rep.SourceHash, rep.ReportDigest, rep.AnalyzerVersion, rep.Counts)
		return map[string]any{
			"report":            rep,
			"attestationDigest": digest,
			"chainId":           a.ChainID,
		}, false

	case "ironclad_scan_remote":
		var a struct {
			PkgPath string `json:"pkgPath"`
			RPCURL  string `json:"rpcUrl"`
			ChainID string `json:"chainId"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil || strings.TrimSpace(a.PkgPath) == "" {
			return map[string]any{"error": "pkgPath is required"}, true
		}
		rpc := firstNonEmpty(a.RPCURL, cfg.RPC)
		chainID := firstNonEmpty(a.ChainID, cfg.ChainID)
		files, err := analyzer.FetchRemotePackage(ctx, rpc, a.PkgPath)
		if err != nil {
			return map[string]any{"error": err.Error()}, true
		}
		rep := analyzer.AnalyzeSources(a.PkgPath, files)
		digest := analyzer.AttestationDigest(chainID, rep.Target, rep.SourceHash, rep.ReportDigest, rep.AnalyzerVersion, rep.Counts)
		return map[string]any{
			"report":            rep,
			"attestationDigest": digest,
			"chainId":           chainID,
			"rpcUrl":            rpc,
		}, false

	case "ironclad_verify_attestation":
		var a struct {
			PkgPath       string `json:"pkgPath"`
			RPCURL        string `json:"rpcUrl"`
			IroncladRealm string `json:"ironcladRealm"`
			ChainID       string `json:"chainId"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil || strings.TrimSpace(a.PkgPath) == "" {
			return map[string]any{"error": "pkgPath is required"}, true
		}
		rpc := firstNonEmpty(a.RPCURL, cfg.RPC)
		realm := firstNonEmpty(a.IroncladRealm, cfg.Realm)
		chainID := firstNonEmpty(a.ChainID, cfg.ChainID)

		attRaw, err := analyzer.FetchRemoteAttestation(ctx, rpc, realm, a.PkgPath)
		if err != nil {
			return map[string]any{"error": "fetch on-chain attestation: " + err.Error()}, true
		}
		var onChain map[string]any
		if err := json.Unmarshal([]byte(attRaw), &onChain); err != nil {
			return map[string]any{"error": "decode on-chain attestation: " + err.Error()}, true
		}
		if _, notFound := onChain["error"]; notFound {
			return map[string]any{"verifiedMatch": false, "reason": "no on-chain attestation found", "onChain": onChain}, false
		}
		files, err := analyzer.FetchRemotePackage(ctx, rpc, a.PkgPath)
		if err != nil {
			return map[string]any{"error": "fetch remote package source: " + err.Error()}, true
		}
		rep := analyzer.AnalyzeSources(a.PkgPath, files)
		recomputedDigest := analyzer.AttestationDigest(chainID, rep.Target, rep.SourceHash, rep.ReportDigest, rep.AnalyzerVersion, rep.Counts)

		onSource, _ := onChain["sourceHash"].(string)
		onReport, _ := onChain["reportDigest"].(string)
		onDigest, _ := onChain["digest"].(string)
		if onDigest == "" {
			onDigest, _ = onChain["attestDigest"].(string)
		}
		match := onSource == rep.SourceHash && onReport == rep.ReportDigest && onDigest == recomputedDigest

		return map[string]any{
			"verifiedMatch":    match,
			"pkgPath":          a.PkgPath,
			"chainId":          chainID,
			"recomputedSource": rep.SourceHash,
			"recomputedReport": rep.ReportDigest,
			"recomputedDigest": recomputedDigest,
			"grade":            rep.Grade,
			"score":            rep.Score,
			"onChain":          onChain,
		}, false

	default:
		return map[string]any{"error": fmt.Sprintf("unknown tool: %s", name)}, true
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
