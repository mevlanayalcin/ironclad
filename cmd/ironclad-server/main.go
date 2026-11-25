// Command ironclad-server serves the live Ironclad Web Security Scanner API
// and static UI, enabling instant analysis of pasted .gno code or live onyx-1
// realms fetched via vm/qfile alongside on-chain attestation lookup.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mevlanayalcin/ironclad/pkg/analyzer"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8502", "HTTP listen address")
	defaultRPC := flag.String("rpc", "https://rpc.onyx.testnets.gno.land:443", "Default Gno RPC URL")
	attestRealm := flag.String("realm", "", "Deployed Ironclad attestation realm path")
	webDir := flag.String("web", "web", "Static web directory")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"version": analyzer.AnalyzerVersion,
			"rpc":     *defaultRPC,
			"realm":   *attestRealm,
		})
	})

	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, analyzer.RuleCatalog)
	})

	mux.HandleFunc("POST /api/scan/source", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target   string `json:"target"`
			Filename string `json:"filename"`
			Source   string `json:"source"`
			ChainID  string `json:"chainId"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if req.Filename == "" {
			req.Filename = "realm.gno"
		}
		if req.Target == "" {
			req.Target = "gno.land/r/sandbox/contract"
		}
		if req.ChainID == "" {
			req.ChainID = "onyx-1"
		}
		rep := analyzer.AnalyzeSources(req.Target, map[string]string{req.Filename: req.Source})
		digest := analyzer.AttestationDigest(req.ChainID, rep.Target, rep.SourceHash, rep.ReportDigest, rep.AnalyzerVersion, rep.Counts)
		writeJSON(w, http.StatusOK, map[string]any{
			"report":            rep,
			"attestationDigest": digest,
		})
	})

	mux.HandleFunc("POST /api/scan/remote", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RPC     string `json:"rpc"`
			PkgPath string `json:"pkgPath"`
			ChainID string `json:"chainId"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if req.RPC == "" {
			req.RPC = *defaultRPC
		}
		if req.ChainID == "" {
			req.ChainID = "onyx-1"
		}
		files, err := analyzer.FetchRemotePackage(r.Context(), req.RPC, req.PkgPath)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		rep := analyzer.AnalyzeSources(req.PkgPath, files)
		digest := analyzer.AttestationDigest(req.ChainID, rep.Target, rep.SourceHash, rep.ReportDigest, rep.AnalyzerVersion, rep.Counts)
		var attRaw json.RawMessage
		if *attestRealm != "" {
			if raw, err := analyzer.FetchRemoteAttestation(r.Context(), req.RPC, *attestRealm, req.PkgPath); err == nil && json.Valid([]byte(raw)) {
				attRaw = json.RawMessage(raw)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"report":             rep,
			"attestationDigest":  digest,
			"onChainAttestation": attRaw,
		})
	})

	if _, err := os.Stat(*webDir); err == nil {
		mux.Handle("/", http.FileServer(http.Dir(*webDir)))
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("ironclad-server listening on http://%s", *listen)
	log.Fatal(srv.ListenAndServe())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
