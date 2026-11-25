package analyzer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type abciResp struct {
	Result struct {
		Response struct {
			ResponseBase struct {
				Error any    `json:"Error"`
				Data  string `json:"Data"`
				Log   string `json:"Log"`
			} `json:"ResponseBase"`
		} `json:"response"`
	} `json:"result"`
}

func abciQuery(ctx context.Context, rpcURL, path, data string) (string, error) {
	u := fmt.Sprintf(
		"%s/abci_query?path=%s&data=0x%s",
		strings.TrimRight(rpcURL, "/"),
		url.QueryEscape(`"`+path+`"`),
		hex.EncodeToString([]byte(data)),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rpc status %d: %s", resp.StatusCode, string(raw))
	}
	var env abciResp
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", err
	}
	rb := env.Result.Response.ResponseBase
	if rb.Error != nil {
		return "", fmt.Errorf("abci error: %v (%s)", rb.Error, rb.Log)
	}
	if rb.Data == "" {
		return "", nil
	}
	dec, err := base64.StdEncoding.DecodeString(rb.Data)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

// FetchRemotePackage retrieves all non-test .gno files for a live deployed
// package/realm from any Gno RPC endpoint via ABCI vm/qfile.
func FetchRemotePackage(ctx context.Context, rpcURL, pkgPath string) (map[string]string, error) {
	pkgPath = strings.Trim(pkgPath, "/")
	listing, err := abciQuery(ctx, rpcURL, "vm/qfile", pkgPath)
	if err != nil {
		return nil, fmt.Errorf("list package %s: %w", pkgPath, err)
	}
	files := make(map[string]string)
	for _, line := range strings.Split(listing, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || !strings.HasSuffix(name, ".gno") || strings.HasSuffix(name, "_test.gno") || strings.HasSuffix(name, "_filetest.gno") {
			continue
		}
		src, err := abciQuery(ctx, rpcURL, "vm/qfile", pkgPath+"/"+name)
		if err != nil {
			return nil, fmt.Errorf("fetch %s/%s: %w", pkgPath, name, err)
		}
		files[name] = src
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .gno files found at %s", pkgPath)
	}
	return files, nil
}

// FetchRemoteAttestation queries a deployed Ironclad realm for an existing
// on-chain attestation covering pkgPath.
func FetchRemoteAttestation(ctx context.Context, rpcURL, ironcladRealm, pkgPath string) (string, error) {
	return abciQuery(ctx, rpcURL, "vm/qrender", strings.Trim(ironcladRealm, "/")+":json/pkg/"+strings.Trim(pkgPath, "/"))
}
