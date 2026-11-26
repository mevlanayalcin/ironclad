const $ = (id) => document.getElementById(id);

const VULN_SAMPLE = `package demo

import (
	"chain/banker"
	"chain/runtime/unsafe"
	"gno.land/p/nt/avl/v0"
	"gno.land/p/nt/grc20/v0"
)

type UnsafeHook interface {
	OnTransfer(cur realm, amt int64)
	isCanonical()
}

var (
	VaultStore = avl.NewTree()
	savedRealm realm
)

func IssueTokens(cur realm, caller address, teller grc20.Teller, cb func(realm)) *avl.Tree {
	_ = unsafe.PreviousRealm()
	if !cur.Previous().IsUser() {
		panic("not user")
	}
	_ = unsafe.OriginSend()
	teller.Transfer(caller, 100)
	cb(cur)
	_ = banker.NewReadonlyBanker().GetCoins(caller).AmountOf("ugnot")
	VaultStore.Iterate("", "", func(k string, v any) bool { return false })
	return VaultStore
}

func Render(path string) string {
	VaultStore.Set("last", path)
	return "# Vault: " + path
}
`;

const SAFE_SAMPLE = `package clean

import (
	"chain/banker"
	"chain/runtime/unsafe"
	"gno.land/p/nt/avl/v0"
	"gno.land/p/nt/markdown/sanitize/v0"
)

var store = avl.NewTree()

func Deposit(cur realm) {
	if !cur.IsCurrent() {
		panic("spoofed realm")
	}
	if !cur.Previous().IsUserCall() {
		panic("direct user call only")
	}
	amt := unsafe.OriginSend().AmountOf("ugnot")
	if amt <= 0 {
		panic("positive deposit required")
	}
	_ = banker.NewReadonlyBanker().GetCoin(cur.Address(), "ugnot")
	store.Set(cur.Previous().Address().String(), amt)
}

func Render(path string) string {
	return "# Clean Vault: " + sanitize.InlineText(path)
}
`;

let backendOnline = false;
let wasmReady = false;
let attestRealmPath = "gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad";

function esc(s) {
  return String(s).replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function toHexUtf8(str) {
  return Array.from(new TextEncoder().encode(str)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function abciQuery(rpcUrl, path, data) {
  const cleanRpc = rpcUrl.replace(/\/+$/, "");
  const u = `${cleanRpc}/abci_query?path=${encodeURIComponent(`"${path}"`)}&data=0x${toHexUtf8(data)}`;
  const res = await fetch(u);
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const env = await res.json();
  const base = env?.result?.response?.ResponseBase;
  if (base?.Error) throw new Error(JSON.stringify(base.Error));
  if (!base?.Data) return "";
  const bin = atob(base.Data);
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

async function fetchRemoteFilesClient(rpcUrl, pkgPath) {
  const clean = pkgPath.replace(/^\/+|\/+$/g, "");
  const listing = await abciQuery(rpcUrl, "vm/qfile", clean);
  const files = {};
  for (const rawLine of listing.split("\n")) {
    const name = rawLine.trim();
    if (!name || !name.endsWith(".gno") || name.endsWith("_test.gno") || name.endsWith("_filetest.gno")) continue;
    files[name] = await abciQuery(rpcUrl, "vm/qfile", `${clean}/${name}`);
  }
  if (!Object.keys(files).length) throw new Error(`No .gno files at ${clean}`);
  return files;
}

async function initWASM() {
  if (typeof Go === "undefined") return false;
  try {
    const go = new Go();
    const res = await fetch("ironclad.wasm");
    if (!res.ok) return false;
    const mod = await WebAssembly.instantiateStreaming(res, go.importObject);
    go.run(mod.instance);
    wasmReady = typeof window.ironcladAnalyzeWASM === "function";
    return wasmReady;
  } catch (e) {
    console.warn("WASM init failed:", e);
    return false;
  }
}

function runWASMAnalyze(target, chainId, filesMap) {
  const raw = window.ironcladAnalyzeWASM(target, chainId, JSON.stringify(filesMap));
  const parsed = JSON.parse(raw);
  if (parsed.error) throw new Error(parsed.error);
  return parsed;
}

function renderResult(data) {
  const rep = data.report;
  const gb = $("gradeBox");
  gb.textContent = rep.grade;
  gb.className = "grade-box" + (rep.grade === "F" || rep.grade === "D" ? " bad" : rep.grade === "C" || rep.grade === "B" ? " mid" : "");
  $("verdictTitle").textContent = `${rep.target} — ${rep.score}/100 (${rep.grade})`;
  $("verdictMeta").textContent =
    `Files: ${rep.filesScanned} · Critical: ${rep.counts.critical} · High: ${rep.counts.high} · Medium: ${rep.counts.medium} · Low: ${rep.counts.low}`;
  $("digestLine").textContent = `sourceHash=${rep.sourceHash.slice(0, 18)}…  reportDigest=${rep.reportDigest.slice(0, 18)}…  attestDigest=${(data.attestationDigest || "").slice(0, 18)}…`;

  const list = $("findingsList");
  if (!rep.findings || rep.findings.length === 0) {
    list.innerHTML = `<div class="finding" style="border-left-color:var(--ok)"><div class="meta">PASS — 0 findings across all 15 Go AST security &amp; lint rules.</div></div>`;
  } else {
    list.innerHTML = rep.findings.map((f) => `
      <div class="finding ${esc(f.severity)}">
        <div class="meta"><strong>[${esc(f.severity)}] ${esc(f.ruleId)}</strong> · ${esc(f.threatClass)} · <code>${esc(f.file)}:${f.line}</code></div>
        <div>${esc(f.message)}</div>
        ${f.snippet ? `<div style="margin-top:4px"><code>${esc(f.snippet)}</code></div>` : ""}
        <div class="fix">Fix: ${esc(f.remediation)}</div>
      </div>`).join("");
  }

  $("attestationBox").textContent = data.onChainAttestation
    ? JSON.stringify(data.onChainAttestation, null, 2)
    : JSON.stringify({
        status: "ready_to_publish",
        attestationDigest: data.attestationDigest,
        sourceHash: rep.sourceHash,
        reportDigest: rep.reportDigest,
      }, null, 2);
}

async function scanSource() {
  try {
    if (backendOnline) {
      const res = await fetch("/api/scan/source", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: "gno.land/r/sandbox/contract", filename: "contract.gno", source: $("sourceArea").value }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "scan error");
      renderResult(data);
      return;
    }
    if (!wasmReady) throw new Error("Go WASM engine still loading — please retry in a moment.");
    renderResult(runWASMAnalyze("gno.land/r/sandbox/contract", "onyx-1", { "contract.gno": $("sourceArea").value }));
  } catch (err) {
    $("verdictTitle").textContent = "Scan error";
    $("verdictMeta").textContent = err.message;
  }
}

async function scanRemote(pkgOverride) {
  if (pkgOverride) $("pkgInput").value = pkgOverride;
  const rpc = $("rpcInput").value.trim();
  const pkgPath = $("pkgInput").value.trim();
  $("verdictTitle").textContent = "Fetching live package via vm/qfile…";
  try {
    if (backendOnline) {
      const res = await fetch("/api/scan/remote", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rpc, pkgPath }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Remote scan error");
      renderResult(data);
      return;
    }
    if (!wasmReady) throw new Error("Go WASM engine not loaded");
    const files = await fetchRemoteFilesClient(rpc, pkgPath);
    const data = runWASMAnalyze(pkgPath, "onyx-1", files);
    try {
      const attRaw = await abciQuery(rpc, "vm/qrender", `${attestRealmPath}:json/pkg/${pkgPath}`);
      if (attRaw && !attRaw.includes('"error":"not_found"')) {
        data.onChainAttestation = JSON.parse(attRaw);
      }
    } catch {}
    renderResult(data);
  } catch (err) {
    $("gradeRing").textContent = "!";
    $("gradeRing").className = "grade-ring g-F";
    $("verdictTitle").textContent = "Remote scan error";
    $("verdictMeta").textContent = err.message;
    $("findingsList").innerHTML = `<div class="finding info">No scan report produced — verify package path is active on the selected RPC.</div>`;
    if ($("sourceHashOut")) $("sourceHashOut").textContent = "—";
    if ($("reportDigestOut")) $("reportDigestOut").textContent = "—";
    if ($("attestDigestOut")) $("attestDigestOut").textContent = "—";
    if ($("attestStatus")) $("attestStatus").textContent = "—";
  }
}

$("loadVulnBtn").addEventListener("click", () => { $("sourceArea").value = VULN_SAMPLE; scanSource(); });
$("loadSafeBtn").addEventListener("click", () => { $("sourceArea").value = SAFE_SAMPLE; scanSource(); });
$("scanSourceBtn").addEventListener("click", scanSource);
$("scanRemoteBtn").addEventListener("click", () => scanRemote());
$("scanNameregBtn").addEventListener("click", () => scanRemote("gno.land/r/sys/namereg/v0"));
$("scanBlogBtn").addEventListener("click", () => scanRemote("gno.land/r/gnoland/blog"));
$("scanTollgateBtn").addEventListener("click", () => {
  const cur = $("pkgInput").value;
  const addrMatch = cur.match(/g1[a-z0-9]{38}/);
  const addr = addrMatch ? addrMatch[0] : "g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2";
  scanRemote(`gno.land/r/${addr}/tollgate/v2`);
});

$("sourceArea").value = VULN_SAMPLE;
(async () => {
  const isStaticHost = location.hostname.endsWith("github.io") || location.protocol === "file:";
  if (!isStaticHost) try {
    const r = await fetch("/api/health");
    if (r.ok) {
      const h = await r.json();
      if (h && h.ok) {
        backendOnline = true;
        $("healthBadge").textContent = `Engine: ${h.version} (Go Server API)`;
        if (h.rpc) $("rpcInput").value = h.rpc;
        if (h.realm) { $("pkgInput").value = h.realm; attestRealmPath = h.realm; }
        await scanSource();
        return;
      }
    }
  } catch {}
  const ok = await initWASM();
  $("healthBadge").textContent = ok ? "Engine: Go AST (WebAssembly 1:1 CLI Parity)" : "Engine: offline";
  if (ok) await scanSource();
})();
