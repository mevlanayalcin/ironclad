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

func Deposit(cur realm, caller address, teller grc20.Teller, cb func()) *avl.Tree {
	_ = unsafe.PreviousRealm()
	if !cur.Previous().IsUser() {
		panic("not user")
	}
	_ = unsafe.OriginSend()
	teller.Transfer(caller, 100)
	cb()
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
let attestRealmPath = "gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad";

function esc(s) {
  return String(s).replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function toHexUtf8(str) {
  return Array.from(new TextEncoder().encode(str)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function lp(s) {
  return `${new TextEncoder().encode(s).length}:${s}|`;
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

// Standalone browser analyzer fallback when hosted statically on GitHub Pages
async function analyzeClientSide(target, filesMap) {
  const findings = [];
  const allSrc = Object.values(filesMap).join("\n");
  const hasSanitize = allSrc.includes("markdown/sanitize");
  const hasGuardHelper = /func\s+\w+\([^)]*realm[^)]*\)[^{]*\{[\s\S]*?\.IsCurrent\(\)/.test(allSrc);
  const names = Object.keys(filesMap).sort();

  const add = (ruleId, threatClass, severity, file, line, message, snippet, remediation) => {
    findings.push({ ruleId, threatClass, severity, title: ruleId, message, file, line, column: 1, snippet, remediation });
  };

  for (const file of names) {
    const lines = filesMap[file].split("\n");
    let inInterface = false;
    let inRender = false;
    let braceDepth = 0;

    lines.forEach((rawLine, idx) => {
      const lineNo = idx + 1;
      const t = rawLine.trim();
      if (/^type\s+\w+\s+interface\s*\{/.test(t)) inInterface = true;
      if (inInterface) {
        if (/\brealm\b/.test(t) && /\(/.test(t)) {
          add("GNO-TC1A", "Class-1a", "CRITICAL", file, lineNo, "Interface method accepts realm capability token", t, "Pass caller address derived under cur.IsCurrent() instead.");
        }
        if (/^(is\w+|sealed\w*)\(\)/.test(t)) {
          add("GNO-TC3", "Class-3", "HIGH", file, lineNo, "Unexported interface sealing marker is bypassable via embedding in Gno", t, "Use concrete type-switch or IsCanonical* allowlist checks.");
        }
        if (t === "}") inInterface = false;
      }
      if (/^\w+\s+realm\b/.test(t) || /banker\.NewBanker\(/.test(t) && /^\s*\w+\s*=/.test(t)) {
        add("GNO-SEC04", "Capability-Persistence", "CRITICAL", file, lineNo, "Package-level variable persists realm or banker capability", t, "Store address strings and mint bankers fresh inside each call.");
      }
      if (/^(var\s+)?[A-Z]\w*\s*=/.test(t) && !/Err\w+\s*=.*New\(/.test(t) && !t.startsWith("const ")) {
        add("GLOBAL001", "Lint-Encapsulation", "MEDIUM", file, lineNo, "Exported mutable global variable in realm", t, "Make package-level mutable variables unexported.");
      }
      if (/^func\s+[A-Z]\w*\([^)]*cur\s+realm/.test(t)) {
        if (!hasGuardHelper && !allSrc.includes(".IsCurrent()")) {
          add("GNO-SEC01", "Class-2", "CRITICAL", file, lineNo, "Exported crossing function missing cur.IsCurrent() guard", t, "Call if !cur.IsCurrent() { panic(...) }.");
        }
        if (/\b(caller|sender|owner|admin)\s+address\b/.test(t)) {
          add("GNO-TC2", "Class-2", "CRITICAL", file, lineNo, "Exported function trusts caller-supplied address parameter", t, "Derive identity from cur.Previous().Address().");
        }
        if (/\b\w+\s+(grc20\.Teller|banker\.Banker)\b/.test(t) && !allSrc.includes("IsCanonical")) {
          add("GNO-TC3", "Class-3", "HIGH", file, lineNo, "Unchecked open interface parameter without IsCanonical* check", t, "Validate canonical implementation via IsCanonical* or type switch.");
        }
        if (/\bfunc\(/.test(t)) {
          add("GNO-TC4", "Class-4", "HIGH", file, lineNo, "Caller-supplied callback parameter executed with realm authority", t, "Avoid executing untrusted func() callbacks under realm authority.");
        }
        if (/\)\s*\*[A-Za-z0-9_.]+/.test(t)) {
          add("GNO-SEC03", "Write-Authority-Leak", "HIGH", file, lineNo, "Exported function returns pointer to mutable state / /p/ mutator", t, "Return value copies or scalar getters instead.");
        }
      }
      if (/\.IsUser\(\)/.test(t)) {
        add("GNO-SEC02", "Class-2", "CRITICAL", file, lineNo, "IsUser() permits ephemeral MsgRun realms; use IsUserCall()", t, "Replace IsUser() with cur.Previous().IsUserCall().");
      }
      if (/unsafe\.(PreviousRealm|CurrentRealm|OriginCaller)\(/.test(t)) {
        add("GNO-SEC05", "Class-2", "HIGH", file, lineNo, "Stack-walking chain/runtime/unsafe identity used", t, "Use cur.Previous() / cur.Address() under cur.IsCurrent().");
      }
      if (/\.GetCoins\([^)]*\)\.AmountOf\(/.test(t)) {
        add("GNO-SEC07", "Gas-DoS", "MEDIUM", file, lineNo, "Unbounded GetCoins().AmountOf() risks unsolicited-denom gas DoS", t, "Use O(1) banker.GetCoin(addr, denom).");
      }
      if (/\.(Iterate|ReverseIterate)\(\s*""\s*,\s*""\s*,/.test(t)) {
        add("AVL001", "Lint-DoS", "MEDIUM", file, lineNo, "Unbounded avl.Tree iteration without offset/limit cap", t, "Use IterateByOffset / ReverseIterateByOffset.");
      }
      if (/^func\s+Render\(/.test(t)) {
        inRender = true;
        braceDepth = 0;
        if (!hasSanitize) {
          add("GNO-SEC06", "Markdown-Injection", "MEDIUM", file, lineNo, "Render(path) omits gno.land/p/nt/markdown/sanitize/v0", t, "Sanitize user/path output with sanitize.InlineText / TableCell.");
        }
      }
      if (inRender) {
        braceDepth += (t.match(/\{/g) || []).length - (t.match(/\}/g) || []).length;
        if (/\.(Set|Remove|SendCoins)\(/.test(t)) {
          add("RENDER001", "Lint-Purity", "MEDIUM", file, lineNo, "State mutation detected inside Render(path)", t, "Keep Render strictly read-only.");
        }
        if (braceDepth <= 0 && t.includes("}")) inRender = false;
      }
    });
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const ruleSet = new Set();
  for (const f of findings) {
    ruleSet.add(f.ruleId);
    counts[f.severity.toLowerCase()]++;
  }
  const penalty = counts.critical * 30 + counts.high * 15 + counts.medium * 6 + counts.low * 2;
  const score = Math.max(0, 100 - penalty);
  const grade =
    score === 100 && !counts.critical && !counts.high ? "A+" :
    score >= 90 && !counts.critical && !counts.high ? "A" :
    score >= 80 && !counts.critical ? "B" :
    score >= 65 && !counts.critical ? "C" :
    score >= 45 ? "D" : "F";

  let srcPre = "";
  for (const n of names) srcPre += `${lp(n)}${new TextEncoder().encode(filesMap[n]).length}:${filesMap[n]}\n`;
  const sourceHash = await sha256Hex(srcPre);
  const reportDigest = await sha256Hex(JSON.stringify(findings));
  const attPre = `ironclad-attestation-v1|${lp("onyx-1")}${lp(target)}${lp(sourceHash)}${lp(reportDigest)}${lp("ironclad-1.0.0")}${counts.critical}|${counts.high}|${counts.medium}|${counts.low}|${counts.info}`;
  const attestationDigest = await sha256Hex(attPre);

  return {
    report: { target, analyzerVersion: "ironclad-1.0.0 (browser)", filesScanned: names.length, sourceHash, reportDigest, counts, score, grade, rulesTriggered: [...ruleSet].sort(), findings },
    attestationDigest,
  };
}

function renderResult(data) {
  const rep = data.report;
  const gb = $("gradeBox");
  gb.textContent = rep.grade;
  gb.className = "grade-box" + (rep.grade === "F" || rep.grade === "D" ? " bad" : rep.grade === "C" || rep.grade === "B" ? " mid" : "");
  $("verdictTitle").textContent = `${rep.target} — ${rep.score}/100 (${rep.grade})`;
  $("verdictMeta").textContent =
    `Files: ${rep.filesScanned} · Critical: ${rep.counts.critical} · High: ${rep.counts.high} · Medium: ${rep.counts.medium} · Low: ${rep.counts.low}`;
  $("digestLine").textContent = `sourceHash=${rep.sourceHash.slice(0, 18)}…  attestDigest=${(data.attestationDigest || "").slice(0, 18)}…`;

  const list = $("findingsList");
  if (!rep.findings || rep.findings.length === 0) {
    list.innerHTML = `<div class="finding" style="border-left-color:var(--ok)"><div class="meta">PASS — 0 findings across all 15 Gno Threat-Class &amp; Lint rules.</div></div>`;
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
    const data = await analyzeClientSide("gno.land/r/sandbox/contract", { "contract.gno": $("sourceArea").value });
    renderResult(data);
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
    const files = await fetchRemoteFilesClient(rpc, pkgPath);
    const data = await analyzeClientSide(pkgPath, files);
    try {
      const attRaw = await abciQuery(rpc, "vm/qrender", `${attestRealmPath}:json/pkg/${pkgPath}`);
      if (attRaw && !attRaw.includes('"error":"not_found"')) {
        data.onChainAttestation = JSON.parse(attRaw);
      }
    } catch {}
    renderResult(data);
  } catch (err) {
    $("verdictTitle").textContent = "Remote scan error";
    $("verdictMeta").textContent = err.message;
  }
}

$("loadVulnBtn").addEventListener("click", () => { $("sourceArea").value = VULN_SAMPLE; scanSource(); });
$("loadSafeBtn").addEventListener("click", () => { $("sourceArea").value = SAFE_SAMPLE; scanSource(); });
$("scanSourceBtn").addEventListener("click", scanSource);
$("scanRemoteBtn").addEventListener("click", () => scanRemote());
$("scanNameregBtn").addEventListener("click", () => scanRemote("gno.land/r/sys/namereg/v0"));
$("scanTollgateBtn").addEventListener("click", () => {
  const cur = $("pkgInput").value;
  const addrMatch = cur.match(/g1[a-z0-9]{38}/);
  const addr = addrMatch ? addrMatch[0] : "g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2";
  scanRemote(`gno.land/r/${addr}/tollgate`);
});

$("sourceArea").value = VULN_SAMPLE;
fetch("/api/health").then((r) => r.ok ? r.json() : null).then((h) => {
  if (h && h.ok) {
    backendOnline = true;
    $("healthBadge").textContent = `Analyzer: ${h.version} (Go AST)`;
    if (h.rpc) $("rpcInput").value = h.rpc;
    if (h.realm) { $("pkgInput").value = h.realm; attestRealmPath = h.realm; }
  } else {
    $("healthBadge").textContent = "Analyzer: Standalone WebCrypto + RPC";
  }
}).catch(() => {
  $("healthBadge").textContent = "Analyzer: Standalone WebCrypto + RPC";
}).finally(scanSource);
