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

function esc(s) {
  return String(s).replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
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
  const res = await fetch("/api/scan/source", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: "gno.land/r/sandbox/contract", filename: "contract.gno", source: $("sourceArea").value }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "scan error");
  renderResult(data);
}

async function scanRemote(pkgOverride) {
  if (pkgOverride) $("pkgInput").value = pkgOverride;
  $("verdictTitle").textContent = "Fetching live package via vm/qfile…";
  const res = await fetch("/api/scan/remote", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rpc: $("rpcInput").value.trim(), pkgPath: $("pkgInput").value.trim() }),
  });
  const data = await res.json();
  if (!res.ok) {
    $("verdictTitle").textContent = "Remote scan error";
    $("verdictMeta").textContent = data.error || "Unknown error";
    return;
  }
  renderResult(data);
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
fetch("/api/health").then((r) => r.json()).then((h) => {
  $("healthBadge").textContent = `Analyzer: ${h.version}`;
  if (h.rpc) $("rpcInput").value = h.rpc;
  if (h.realm) $("pkgInput").value = h.realm;
}).catch(() => {
  $("healthBadge").textContent = "Analyzer: start ironclad-server";
});
