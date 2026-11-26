package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mevlanayalcin/ironclad/pkg/analyzer"
)

func TestMCPHandshakeNotificationAndTools(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ironclad_list_rules","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ironclad_scan_source","arguments":{"source":"package demo\nfunc Render(path string) string { return \"# \" + path }\n"}}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	serveMCP(context.Background(), strings.NewReader(input), &out, mcpConfig{
		RPC: "http://127.0.0.1:1", Realm: "gno.land/r/test/ironclad", ChainID: "onyx-1",
	})

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 responses (notification skipped), got %d:\n%s", len(lines), out.String())
	}

	var r2 map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &r2); err != nil {
		t.Fatalf("unmarshal tools/list: %v", err)
	}
	tools := r2["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("expected 4 MCP tools, got %d", len(tools))
	}

	var r4 map[string]any
	if err := json.Unmarshal([]byte(lines[3]), &r4); err != nil {
		t.Fatalf("unmarshal scan_source: %v", err)
	}
	res := r4["result"].(map[string]any)
	if res["isError"].(bool) {
		t.Fatalf("unexpected tool error: %v", res)
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "GNO-SEC06") {
		t.Fatalf("expected GNO-SEC06 finding in scan output, got %s", text)
	}
}

func TestMCPVerifyAttestationMatchAndTamper(t *testing.T) {
	cleanSrc := "package safe\n\nfunc Hello() string { return \"ok\" }\n"
	target := "gno.land/r/demo/safe"
	rep := analyzer.AnalyzeSources(target, map[string]string{"safe.gno": cleanSrc})
	validDigest := analyzer.AttestationDigest("onyx-1", target, rep.SourceHash, rep.ReportDigest, rep.AnalyzerVersion, rep.Counts)

	tampered := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qPath := strings.Trim(r.URL.Query().Get("path"), `"`)
		rawHex := strings.TrimPrefix(r.URL.Query().Get("data"), "0x")
		argBytes, _ := hex.DecodeString(rawHex)
		arg := string(argBytes)

		var payload string
		switch {
		case qPath == "vm/qfile" && arg == target:
			payload = "safe.gno\n"
		case qPath == "vm/qfile" && arg == target+"/safe.gno":
			payload = cleanSrc
		case qPath == "vm/qrender" && strings.HasSuffix(arg, ":json/pkg/"+target):
			d := validDigest
			if tampered {
				d = strings.Repeat("0", 64)
			}
			b, _ := json.Marshal(map[string]any{
				"id":           1,
				"pkgPath":      target,
				"sourceHash":   rep.SourceHash,
				"reportDigest": rep.ReportDigest,
				"digest": d,
				"grade":        rep.Grade,
				"score":        rep.Score,
			})
			payload = string(b)
		default:
			http.Error(w, "unknown query: "+qPath+" "+arg, http.StatusNotFound)
			return
		}
		enc := base64.StdEncoding.EncodeToString([]byte(payload))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"response": map[string]any{
					"ResponseBase": map[string]any{"Data": enc},
				},
			},
		})
	}))
	defer srv.Close()

	cfg := mcpConfig{RPC: srv.URL, Realm: "gno.land/r/test/ironclad", ChainID: "onyx-1"}
	args, _ := json.Marshal(map[string]any{"pkgPath": target})

	out, isErr := executeMCPTool(context.Background(), "ironclad_verify_attestation", args, cfg)
	if isErr || !out.(map[string]any)["verifiedMatch"].(bool) {
		t.Fatalf("expected verifiedMatch=true, got err=%v out=%+v", isErr, out)
	}

	tampered = true
	out2, isErr2 := executeMCPTool(context.Background(), "ironclad_verify_attestation", args, cfg)
	if isErr2 || out2.(map[string]any)["verifiedMatch"].(bool) {
		t.Fatalf("expected tampered verifiedMatch=false, got err=%v out=%+v", isErr2, out2)
	}
}
