const $ = (id) => document.getElementById(id);

const IRONCLAD_REALM = "gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad";
const DEFAULT_RPC = "https://rpc.onyx.testnets.gno.land:443";
const CHAIN_ID = "onyx-1";

let wasmReady = false;
let adenaAccount = null;
let lastScanData = null;
let registryAttestations = [];
let activeScenarioIdx = 0;

const SCENARIOS = [
  {
    name: "Class-1a/1b: Realm Leak",
    vuln: `package vault

import "gno.land/p/nt/avl/v0"

type UnsafeHook interface {
	OnTransfer(cur realm, amt int64)
}

var savedRealm realm
var store = avl.NewTree()

func StoreCap(cur realm) {
	savedRealm = cur
}
`,
    safe: `package vault

import "gno.land/p/nt/avl/v0"

type SafeHook interface {
	OnTransfer(caller address, amt int64)
}

var store = avl.NewTree()

func RecordAction(cur realm, note string) {
	if !cur.IsCurrent() {
		panic("spoofed realm")
	}
	caller := cur.Previous().Address()
	store.Set(caller.String(), note)
}
`,
  },
  {
    name: "Class-2: Origin / IsUser() Spoof",
    vuln: `package treasury

import (
	"chain/runtime/unsafe"
	"gno.land/p/nt/avl/v0"
)

var balances = avl.NewTree()

func Deposit(cur realm) {
	caller := unsafe.PreviousRealm().Address()
	if !cur.Previous().IsUser() {
		panic("users only")
	}
	coins := unsafe.OriginSend()
	balances.Set(caller.String(), coins.AmountOf("ugnot"))
}
`,
    safe: `package treasury

import (
	"chain/banker"
	"gno.land/p/nt/avl/v0"
)

var balances = avl.NewTree()

func Deposit(cur realm) {
	if !cur.IsCurrent() {
		panic("spoofed realm")
	}
	if !cur.Previous().IsUserCall() {
		panic("direct user call required")
	}
	caller := cur.Previous().Address()
	sent := banker.OriginSend().AmountOf("ugnot")
	balances.Set(caller.String(), sent)
}
`,
  },
  {
    name: "Class-3: Unsealed Interface",
    vuln: `package swap

import "gno.land/p/nt/grc20/v0"

type CustomToken interface {
	Transfer(to address, amt int64) error
	isTrusted()
}

func Settle(cur realm, teller grc20.Teller, to address, amt int64) {
	teller.Transfer(to, amt)
}
`,
    safe: `package swap

import "gno.land/p/nt/avl/v0"

var ledger = avl.NewTree()

func Settle(cur realm, to address, amt int64) {
	if !cur.IsCurrent() {
		panic("spoofed realm")
	}
	if !cur.Previous().IsUserCall() {
		panic("direct user call required")
	}
	if amt <= 0 {
		panic("invalid amount")
	}
	ledger.Set(to.String(), amt)
}
`,
  },
  {
    name: "Class-4: Callback Under Realm",
    vuln: `package router

func ExecuteWithHook(cur realm, cb func(realm)) {
	cb(cur)
}
`,
    safe: `package router

func ExecuteSafe(cur realm, recipient address) string {
	if !cur.IsCurrent() {
		panic("spoofed realm")
	}
	if !cur.Previous().IsUserCall() {
		panic("direct user call required")
	}
	return recipient.String()
}
`,
  },
  {
    name: "Borrow #2 + Banker DoS",
    vuln: `package escrow

import (
	"chain/banker"
	"gno.land/p/nt/avl/v0"
)

var (
	VaultStore = avl.NewTree()
	globalBank = banker.NewBanker(banker.BankerTypeRealmSend)
)

func GetTree() *avl.Tree {
	return VaultStore
}

func BalanceOf(addr address) int64 {
	return banker.NewReadonlyBanker().GetCoins(addr).AmountOf("ugnot")
}
`,
    safe: `package escrow

import (
	"chain/banker"
	"gno.land/p/nt/avl/v0"
)

var vaultStore = avl.NewTree()

func BalanceOf(addr address) int64 {
	b := banker.NewBanker(banker.BankerTypeReadonly)
	return b.GetCoin(addr, "ugnot").Amount
}

func EntryCount() int {
	return vaultStore.Size()
}
`,
  },
  {
    name: "PR #5068: AVL001 + RENDER001 + SEC06",
    vuln: `package board

import "gno.land/p/nt/avl/v0"

var Posts = avl.NewTree()

func Render(path string) string {
	Posts.Set("lastPath", path)
	out := "# Board: " + path + "\\n"
	Posts.Iterate("", "", func(k string, v any) bool {
		out += "- " + k + "\\n"
		return false
	})
	return out
}
`,
    safe: `package board

import (
	"gno.land/p/nt/avl/v0"
	"gno.land/p/nt/markdown/sanitize/v0"
)

var posts = avl.NewTree()

func Render(path string) string {
	out := "# Board: " + sanitize.InlineText(path) + "\\n"
	posts.IterateByOffset(0, 20, func(k string, v any) bool {
		out += "- " + sanitize.InlineText(k) + "\\n"
		return false
	})
	return out
}
`,
  },
];

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function toHexUtf8(str) {
  return Array.from(new TextEncoder().encode(str)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
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
  if (!wasmReady) throw new Error("Go WASM engine is still initializing — please retry in a moment.");
  const raw = window.ironcladAnalyzeWASM(target, chainId, JSON.stringify(filesMap));
  const parsed = JSON.parse(raw);
  if (parsed.error) throw new Error(parsed.error);
  return parsed;
}

// --- Adena Wallet Integration ---
async function connectAdena() {
  if (!window.adena) {
    $("walletStatus").innerHTML = `Adena Wallet extension not detected — install at <a href="https://adena.app" target="_blank" rel="noopener">adena.app</a> or use the copyable <code>gnokey</code> commands below.`;
    return null;
  }
  try {
    await window.adena.AddEstablish("Ironclad Security Suite");
    const acc = await window.adena.GetAccount();
    if (acc?.status !== "success" || !acc?.data?.address) {
      throw new Error(acc?.message || "Failed to read Adena account");
    }
    adenaAccount = acc.data;
    const chainOk = adenaAccount.chainId === CHAIN_ID;
    const shortAddr = `${adenaAccount.address.slice(0, 10)}…${adenaAccount.address.slice(-6)}`;
    $("connectAdenaBtn").textContent = `Adena: ${shortAddr}`;
    $("walletStatus").innerHTML = `Connected <code>${esc(adenaAccount.address)}</code> · Balance: <code>${esc(adenaAccount.coins || "0ugnot")}</code> · Chain: <code>${esc(adenaAccount.chainId || "unknown")}</code>` +
      (chainOk ? ` <span style="color:var(--accent)">(onyx-1 ✓)</span>` : ` <a href="#" id="switchOnyxLink">(Switch to onyx-1)</a>`);
    if (!chainOk && $("switchOnyxLink")) {
      $("switchOnyxLink").addEventListener("click", async (e) => {
        e.preventDefault();
        try {
          await window.adena.SwitchNetwork(CHAIN_ID);
          await connectAdena();
        } catch (err) {
          alert(`SwitchNetwork failed: ${err.message || err}`);
        }
      });
    }
    return adenaAccount;
  } catch (err) {
    $("walletStatus").textContent = `Adena connect error: ${err.message || err}`;
    return null;
  }
}

async function adenaCall(funcName, args, memo) {
  if (!adenaAccount) {
    const acc = await connectAdena();
    if (!acc) throw new Error("Connect Adena Wallet first (https://adena.app).");
  }
  const resp = await window.adena.DoContract({
    messages: [
      {
        type: "/vm.m_call",
        value: {
          caller: adenaAccount.address,
          send: "",
          pkg_path: IRONCLAD_REALM,
          func: funcName,
          args: args.map((a) => String(a)),
        },
      },
    ],
    gasFee: 1000000,
    gasWanted: 35000000,
    memo: memo || `Ironclad ${funcName}`,
  });
  if (resp?.status !== "success") {
    throw new Error(resp?.message || JSON.stringify(resp));
  }
  return resp;
}

// --- Tab Switching ---
function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
}
document.querySelectorAll(".tab-btn").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));

// --- Tab 1: Live On-Chain Registry ---
function gradeClass(g) {
  if (g === "A+" || g === "A") return "g-ok";
  if (g === "B" || g === "C") return "g-warn";
  return "g-bad";
}

async function loadRegistry() {
  const rpc = $("rpcInput").value.trim() || DEFAULT_RPC;
  try {
    const [sumRaw, listRaw] = await Promise.all([
      abciQuery(rpc, "vm/qrender", `${IRONCLAD_REALM}:json/summary`),
      abciQuery(rpc, "vm/qrender", `${IRONCLAD_REALM}:json/attestations`),
    ]);
    const sum = JSON.parse(sumRaw);
    $("statAttest").textContent = sum.attestations ?? "—";
    $("statPkgs").textContent = sum.packages ?? "—";
    $("statAuditors").textContent = sum.auditors ?? "—";
    $("statChallenges").textContent = sum.challenges ?? "—";
    $("statHeight").textContent = sum.height ?? "—";

    const list = JSON.parse(listRaw);
    registryAttestations = Array.isArray(list) ? list : [];
    renderRegistryTable();
  } catch (err) {
    $("registryTableBody").innerHTML = `<tr><td colspan="8" style="color:#fca5a5">Failed to query onyx-1 registry: ${esc(err.message)}</td></tr>`;
  }
}

function renderRegistryTable() {
  const tb = $("registryTableBody");
  if (!registryAttestations.length) {
    tb.innerHTML = `<tr><td colspan="8" class="muted">No on-chain attestations found.</td></tr>`;
    return;
  }
  tb.innerHTML = registryAttestations.map((a) => `
    <tr id="att-row-${a.id}">
      <td class="mono"><a href="https://onyx.testnets.gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad:attestation/${a.id}" target="_blank" rel="noopener">#${a.id}</a></td>
      <td class="mono"><strong>${esc(a.targetPkgPath)}</strong><div style="font-size:0.72rem;color:var(--muted)">digest ${esc((a.digest || "").slice(0, 14))}…</div></td>
      <td><span class="grade-pill ${gradeClass(a.grade)}">${esc(a.grade)} (${a.score})</span></td>
      <td class="mono">${a.critical}/${a.high}/${a.medium}/${a.low}</td>
      <td class="mono">${a.height}</td>
      <td><span class="badge ${a.status === "valid" ? "ok" : "bad"}">${esc(a.status)}${a.challengeCount ? ` · ${a.challengeCount} ch` : ""}</span></td>
      <td id="wasm-proof-${a.id}"><span class="muted">Not checked yet</span></td>
      <td style="white-space:nowrap">
        <button class="sm" onclick="verifyRowWasm(${a.id})">Verify WASM</button>
        <button class="sm secondary" onclick="openInScanner('${esc(a.targetPkgPath)}')">Inspect</button>
        <button class="sm warn-btn" onclick="openChallenge(${a.id})">Challenge</button>
      </td>
    </tr>
  `).join("");
}

window.verifyRowWasm = async function (attId) {
  const a = registryAttestations.find((x) => x.id === attId);
  if (!a) return;
  const cell = $(`wasm-proof-${attId}`);
  cell.innerHTML = `<span class="badge">Fetching vm/qfile…</span>`;
  try {
    const rpc = $("rpcInput").value.trim() || DEFAULT_RPC;
    const files = await fetchRemoteFilesClient(rpc, a.targetPkgPath);
    const out = runWASMAnalyze(a.targetPkgPath, CHAIN_ID, files);
    const match =
      out.report.sourceHash === a.sourceHash &&
      out.report.reportDigest === a.reportDigest &&
      out.attestationDigest === a.digest;
    if (match) {
      cell.innerHTML = `<span class="badge ok" title="SourceSHA256, ReportDigest & AttestDigest match bit-for-bit">VERIFIED ✓ (${out.report.filesScanned} files)</span>`;
    } else {
      cell.innerHTML = `<span class="badge bad" title="On-chain digest mismatch">MISMATCH ✗</span>`;
    }
  } catch (err) {
    cell.innerHTML = `<span class="badge bad">${esc(err.message.slice(0, 40))}</span>`;
  }
};

window.openInScanner = function (pkgPath) {
  $("pkgInput").value = pkgPath;
  switchTab("scanner");
  scanRemote();
};

window.openChallenge = function (attId) {
  $("chAttIdLabel").textContent = String(attId);
  $("challengeBox").dataset.attId = String(attId);
  $("challengeBox").classList.add("open");
  $("challengeTxOut").style.display = "none";
};

$("verifyAllWasmBtn").addEventListener("click", async () => {
  for (const a of registryAttestations) {
    await window.verifyRowWasm(a.id);
  }
});

$("refreshRegistryBtn").addEventListener("click", loadRegistry);
$("registerAuditorBtn").addEventListener("click", () => $("registerAuditorBox").classList.toggle("open"));
$("closeAuditorBtn").addEventListener("click", () => $("registerAuditorBox").classList.remove("open"));
$("closeChallengeBtn").addEventListener("click", () => $("challengeBox").classList.remove("open"));

$("submitAuditorBtn").addEventListener("click", async () => {
  const out = $("auditorTxOut");
  out.style.display = "block";
  const handle = $("audHandleInput").value.trim();
  const bio = $("audBioInput").value.trim();
  const url = $("audUrlInput").value.trim();
  if (!handle) { out.textContent = "Auditor handle is required."; return; }
  out.textContent = "Requesting signature in Adena Wallet…";
  try {
    const resp = await adenaCall("RegisterAuditor", [handle, bio, url], `Ironclad RegisterAuditor ${handle}`);
    out.textContent = `Broadcast success!\n${JSON.stringify(resp.data || resp, null, 2)}`;
    setTimeout(loadRegistry, 3500);
  } catch (err) {
    out.textContent = `Adena error: ${err.message}\n\nCLI fallback:\ngnokey maketx call <key> -broadcast -remote ${DEFAULT_RPC} -chainid ${CHAIN_ID} -pkgpath ${IRONCLAD_REALM} -func RegisterAuditor -args ${JSON.stringify(handle)} -args ${JSON.stringify(bio)} -args ${JSON.stringify(url)}`;
  }
});

$("submitChallengeBtn").addEventListener("click", async () => {
  const out = $("challengeTxOut");
  out.style.display = "block";
  const attId = $("challengeBox").dataset.attId;
  const rule = $("chRuleSelect").value;
  const reason = $("chReasonInput").value.trim();
  if (!reason) { out.textContent = "Technical challenge reason is required."; return; }
  const evidenceDigest = await sha256Hex(`${attId}|${rule}|${reason}`);
  out.textContent = "Requesting signature in Adena Wallet…";
  try {
    const resp = await adenaCall("ChallengeAttestation", [attId, rule, evidenceDigest, reason], `Ironclad Challenge #${attId} (${rule})`);
    out.textContent = `Challenge broadcast success!\n${JSON.stringify(resp.data || resp, null, 2)}`;
    setTimeout(loadRegistry, 3500);
  } catch (err) {
    out.textContent = `Adena error: ${err.message}\n\nCLI fallback:\ngnokey maketx call <key> -broadcast -remote ${DEFAULT_RPC} -chainid ${CHAIN_ID} -pkgpath ${IRONCLAD_REALM} -func ChallengeAttestation -args ${attId} -args ${JSON.stringify(rule)} -args ${JSON.stringify(evidenceDigest)} -args ${JSON.stringify(reason)}`;
  }
});

// --- Tab 2: Live Package Scanner & Adena Publish ---
function renderFindingsInto(container, findings) {
  if (!findings || !findings.length) {
    container.innerHTML = `<div class="finding LOW" style="border-left-color:var(--accent)"><strong>PASS — 0 security or lint findings detected across all 15 Go AST rules.</strong></div>`;
    return;
  }
  container.innerHTML = findings.map((f) => `
    <div class="finding ${esc(f.severity)}">
      <div class="meta"><strong>[${esc(f.severity)}] ${esc(f.ruleId)}</strong> (${esc(f.threatClass)}) · ${esc(f.file)}:${f.line}</div>
      <div>${esc(f.message)}</div>
      ${f.snippet ? `<div style="margin-top:4px"><code>${esc(f.snippet)}</code></div>` : ""}
      <div class="fix">Fix: ${esc(f.remediation)}</div>
    </div>
  `).join("");
}

function renderScannerResult(data) {
  lastScanData = data;
  const rep = data.report;
  const gb = $("gradeBox");
  gb.textContent = rep.grade;
  gb.className = "grade-box" + (rep.grade === "F" || rep.grade === "D" ? " bad" : rep.grade === "B" || rep.grade === "C" ? " warn" : "");
  $("verdictTitle").textContent = `${rep.target} — Grade ${rep.grade} (${rep.score}/100)`;
  $("verdictMeta").textContent = `Files: ${rep.filesScanned} · Critical: ${rep.counts.critical} · High: ${rep.counts.high} · Medium: ${rep.counts.medium} · Low: ${rep.counts.low} · Info: ${rep.counts.info}`;
  $("digestLine").textContent = `SourceSHA256: ${rep.sourceHash.slice(0, 16)}… · ReportDigest: ${rep.reportDigest.slice(0, 16)}… · AttestDigest: ${data.attestationDigest.slice(0, 16)}…`;

  renderFindingsInto($("findingsList"), rep.findings);
  $("publishAdenaBtn").disabled = false;
  $("exportSarifBtn").disabled = false;
  $("exportJsonBtn").disabled = false;

  const rulesCSV = (rep.rulesTriggered || []).join(",");
  const summary = `Ironclad browser WASM audit: Grade ${rep.grade} (${rep.score}/100)`;
  const cliCmd = `ironclad scan --remote ${$("rpcInput").value.trim()} ${rep.target}`;
  const gnokeyCmd =
    `gnokey maketx call <key> -broadcast -remote ${$("rpcInput").value.trim()} -chainid ${CHAIN_ID} \\\n` +
    `  -pkgpath ${IRONCLAD_REALM} -func PublishAttestation \\\n` +
    `  -args ${JSON.stringify(rep.target)} -args ${JSON.stringify(rep.sourceHash)} -args ${JSON.stringify(rep.reportDigest)} -args ${JSON.stringify(rep.analyzerVersion)} \\\n` +
    `  -args ${rep.counts.critical} -args ${rep.counts.high} -args ${rep.counts.medium} -args ${rep.counts.low} -args ${rep.counts.info} \\\n` +
    `  -args ${JSON.stringify(rulesCSV)} -args ${JSON.stringify(summary)} -args "https://github.com/mevlanayalcin/ironclad"`;

  if (data.onChainAttestation && !data.onChainAttestation.error) {
    const oc = data.onChainAttestation;
    const match = oc.sourceHash === rep.sourceHash && oc.reportDigest === rep.reportDigest && oc.digest === data.attestationDigest;
    $("attestationBox").textContent =
      `ON-CHAIN MATCH: ${match ? "CRYPTOGRAPHICALLY VERIFIED ✓ (SourceHash + ReportDigest + AttestDigest identical)" : "DIFFERS FROM LATEST ON-CHAIN RECORD"}\n\n` +
      JSON.stringify(oc, null, 2) +
      `\n\nReproduce via CLI:\n${cliCmd}`;
  } else {
    $("attestationBox").textContent =
      `No on-chain attestation anchored yet for ${rep.target}.\nClick "Publish Attestation (Adena)" above or run:\n\n${gnokeyCmd}\n\nReproduce via CLI:\n${cliCmd}`;
  }
}

async function scanRemote() {
  const rpc = $("rpcInput").value.trim() || DEFAULT_RPC;
  const pkg = $("pkgInput").value.trim();
  $("publishTxOut").style.display = "none";
  $("verdictTitle").textContent = `Fetching live .gno files from ${pkg}…`;
  $("verdictMeta").textContent = `Querying ABCI vm/qfile at ${rpc}`;
  $("digestLine").textContent = "";
  $("findingsList").innerHTML = "";
  try {
    const files = await fetchRemoteFilesClient(rpc, pkg);
    const out = runWASMAnalyze(pkg, CHAIN_ID, files);
    try {
      const attRaw = await abciQuery(rpc, "vm/qrender", `${IRONCLAD_REALM}:json/pkg/${pkg.replace(/^\/+|\/+$/g, "")}`);
      out.onChainAttestation = JSON.parse(attRaw);
    } catch {}
    renderScannerResult(out);
  } catch (err) {
    $("gradeBox").textContent = "!";
    $("gradeBox").className = "grade-box bad";
    $("verdictTitle").textContent = "Remote scan failed";
    $("verdictMeta").textContent = err.message;
  }
}

function buildSarif(rep) {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "Ironclad",
          version: rep.analyzerVersion,
          informationUri: "https://github.com/mevlanayalcin/ironclad",
        },
      },
      results: (rep.findings || []).map((f) => ({
        ruleId: f.ruleId,
        level: f.severity === "CRITICAL" || f.severity === "HIGH" ? "error" : f.severity === "MEDIUM" ? "warning" : "note",
        message: { text: `${f.message} — Fix: ${f.remediation}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine: f.line, startColumn: f.column || 1 },
          },
        }],
      })),
    }],
  };
}

function downloadFile(name, text, mime) {
  const blob = new Blob([text], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

$("scanRemoteBtn").addEventListener("click", scanRemote);
document.querySelectorAll("#quickPkgChips .chip").forEach((c) => {
  c.addEventListener("click", () => {
    $("pkgInput").value = c.dataset.pkg;
    scanRemote();
  });
});

$("exportSarifBtn").addEventListener("click", () => {
  if (!lastScanData) return;
  const slug = lastScanData.report.target.replace(/[^a-zA-Z0-9_-]+/g, "_");
  downloadFile(`${slug}.sarif.json`, JSON.stringify(buildSarif(lastScanData.report), null, 2), "application/sarif+json");
});

$("exportJsonBtn").addEventListener("click", () => {
  if (!lastScanData) return;
  const slug = lastScanData.report.target.replace(/[^a-zA-Z0-9_-]+/g, "_");
  downloadFile(`${slug}.ironclad.json`, JSON.stringify(lastScanData, null, 2), "application/json");
});

$("publishAdenaBtn").addEventListener("click", async () => {
  if (!lastScanData) return;
  const rep = lastScanData.report;
  const out = $("publishTxOut");
  out.style.display = "block";
  out.textContent = "Requesting PublishAttestation signature in Adena Wallet…";
  try {
    const resp = await adenaCall(
      "PublishAttestation",
      [
        rep.target,
        rep.sourceHash,
        rep.reportDigest,
        rep.analyzerVersion,
        String(rep.counts.critical),
        String(rep.counts.high),
        String(rep.counts.medium),
        String(rep.counts.low),
        String(rep.counts.info),
        (rep.rulesTriggered || []).join(","),
        `Ironclad WASM audit on ${CHAIN_ID}: Grade ${rep.grade} (${rep.score}/100)`,
        "https://mevlanayalcin.github.io/ironclad/",
      ],
      `Ironclad PublishAttestation ${rep.target}`
    );
    out.textContent = `Attestation published on onyx-1!\n${JSON.stringify(resp.data || resp, null, 2)}`;
    setTimeout(() => { loadRegistry(); scanRemote(); }, 3500);
  } catch (err) {
    out.textContent = `Publish failed: ${err.message}\n(Note: first-time auditors must click "Register Auditor (Adena)" in Tab 1 once.)`;
  }
});

// --- Tab 3: Interactive Threat-Class Playground ---
function initPlayground() {
  const box = $("scenarioChips");
  box.innerHTML = SCENARIOS.map((s, idx) => `<span class="chip ${idx === 0 ? "active" : ""}" data-idx="${idx}">${esc(s.name)}</span>`).join("");
  box.querySelectorAll(".chip").forEach((el) => {
    el.addEventListener("click", () => {
      activeScenarioIdx = Number(el.dataset.idx);
      box.querySelectorAll(".chip").forEach((x) => x.classList.toggle("active", Number(x.dataset.idx) === activeScenarioIdx));
      $("sourceArea").value = SCENARIOS[activeScenarioIdx].vuln;
      analyzeSandbox();
    });
  });
  $("sourceArea").value = SCENARIOS[0].vuln;
}

function analyzeSandbox() {
  const src = $("sourceArea").value;
  if (!wasmReady) return;
  try {
    const out = runWASMAnalyze("gno.land/r/sandbox/demo", CHAIN_ID, { "contract.gno": src });
    const rep = out.report;
    const gb = $("sbGradeBox");
    gb.textContent = rep.grade;
    gb.className = "grade-box" + (rep.grade === "F" || rep.grade === "D" ? " bad" : rep.grade === "B" || rep.grade === "C" ? " warn" : "");
    $("sbVerdictTitle").textContent = `Grade ${rep.grade} (${rep.score}/100) — ${(rep.findings || []).length} finding(s)`;
    $("sbVerdictMeta").textContent = `SourceSHA256: ${rep.sourceHash.slice(0, 18)}… · Rules: ${(rep.rulesTriggered || []).join(", ") || "none"}`;

    const hitByLine = {};
    for (const f of rep.findings || []) {
      const prev = hitByLine[f.line];
      if (!prev || f.severity === "CRITICAL" || (f.severity === "HIGH" && prev !== "CRITICAL")) {
        hitByLine[f.line] = f.severity;
      }
    }
    const lines = src.split("\n");
    $("sbCodeHighlight").innerHTML = lines.map((line, i) => {
      const ln = i + 1;
      const sev = hitByLine[ln];
      const cls = sev === "CRITICAL" ? "hit-crit" : sev === "HIGH" ? "hit-high" : sev ? "hit-med" : "";
      return `<div class="code-line ${cls}"><span class="ln">${ln}</span><span>${esc(line || " ")}</span></div>`;
    }).join("");

    renderFindingsInto($("sbFindingsList"), rep.findings);
  } catch (err) {
    $("sbVerdictTitle").textContent = "Sandbox error";
    $("sbVerdictMeta").textContent = err.message;
  }
}

$("scanSourceBtn").addEventListener("click", analyzeSandbox);
$("applyFixBtn").addEventListener("click", () => {
  $("sourceArea").value = SCENARIOS[activeScenarioIdx].safe;
  analyzeSandbox();
});
$("restoreVulnBtn").addEventListener("click", () => {
  $("sourceArea").value = SCENARIOS[activeScenarioIdx].vuln;
  analyzeSandbox();
});
$("connectAdenaBtn").addEventListener("click", connectAdena);

// --- Boot ---
(async function boot() {
  initPlayground();
  const ok = await initWASM();
  $("healthBadge").textContent = ok ? "Engine: Go WASM ready ✓" : "Engine: WASM load error";
  if (!ok) $("healthBadge").className = "badge bad";
  if (ok) analyzeSandbox();
  await loadRegistry();
})();
