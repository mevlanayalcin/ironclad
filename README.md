# Ironclad — Gno Smart-Contract Static Security Analyzer & On-Chain Audit Attestation Registry

> Built for the **Gno.land Gnome Tavern Hackathon (Nov–Dec 2026)** on Gno `v1.8.0-rc.1` (`onyx-1`).

**Ironclad** automates Gno.land's official November 2026 security specifications — **[`docs/resources/gno-security.md`](https://github.com/gnolang/gno/blob/master/docs/resources/gno-security.md)**, **[`docs/resources/gno-ai-contract-review.md`](https://github.com/gnolang/gno/blob/master/docs/resources/gno-ai-contract-review.md)**, and **[`gnolang/gno#5068`](https://github.com/gnolang/gno/pull/5068)** (`AVL001`, `GLOBAL001`, `RENDER001`) — pairing a fast Go AST static analyzer (with SARIF v2.1.0 & live `onyx-1` `vm/qfile` scanning) with an **immutable content-addressed on-chain audit attestation registry** on `onyx-1`.

---

## Implemented Rules (15 AST Security & Lint Detectors)

| Rule ID | Severity | Official Gno Threat Class / Spec | What It Catches |
|---|---|---|---|
| `GNO-TC1A` | `CRITICAL` | Class-1a (`gno-security.md`) | Interface methods taking `cur realm` (cur-disclosure / impersonate-self) |
| `GNO-TC1B` | `HIGH` | Class-1b (`gno-security.md`) | Passing live `cur realm` handles into external/untrusted calls (impersonate-caller) |
| `GNO-TC2` | `CRITICAL` | Class-2 (`gno-security.md`) | Designation-forgery: caller-supplied `caller`/`sender` `address` or `pkgPath` parameters |
| `GNO-TC3` | `HIGH` | Class-3 (`gno-security.md`) | Unchecked open interface params (`grc20.Teller`, `banker.Banker`, etc.) & bypassable unexported interface sealing markers |
| `GNO-TC4` | `HIGH` | Class-4 (`gno-security.md`) | Caller-supplied `func(...)` callbacks executed under realm authority |
| `GNO-SEC01` | `CRITICAL` | Review Check #1 | Exported crossing function (`cur realm`) missing `cur.IsCurrent()` guard |
| `GNO-SEC02` | `CRITICAL` | Review Check #2 | Payment handler using `IsUser()` instead of `IsUserCall()` or unguarded `unsafe.OriginSend()` |
| `GNO-SEC03` | `HIGH` | Review Checks #3 & #8 | Exported function returning pointer (`*avl.Tree`, `*State`) leaking borrow-rule #2 write authority |
| `GNO-SEC04` | `CRITICAL` | Review Check #6 & `banker.gno` | Persisting `realm` or `banker.Banker` capabilities in package-level globals |
| `GNO-SEC05` | `HIGH` | Review Check #9 | Using `unsafe.PreviousRealm()` / `CurrentRealm()` / `OriginCaller()` alongside `cur realm` |
| `GNO-SEC06` | `MEDIUM` | Review Check #10 | `Render(path)` concatenating dynamic strings without `gno.land/p/nt/markdown/sanitize/v0` |
| `GNO-SEC07` | `MEDIUM` | Review Check #11 | Unbounded `GetCoins(...).AmountOf(...)` or `GetCoins` in loops (unsolicited-denom gas DoS) |
| `AVL001` | `MEDIUM` | `gnolang/gno#5068` | Unbounded `avl.Tree.Iterate("", "", ...)` / `ReverseIterate` without limit/offset |
| `GLOBAL001` | `MEDIUM` | `gnolang/gno#5068` | Exported mutable global `var` in a `/r/` realm |
| `RENDER001` | `MEDIUM` | `gnolang/gno#5068` | State mutation (`=`, `++`, `.Set()`, `.Remove()`) inside `Render(path)` |

---

## Architecture

```mermaid
flowchart LR
    CLI["ironclad CLI / GitHub SARIF"] -->|vm/qfile live fetch| RPC["onyx-1 / gnodev RPC"]
    Web["Ironclad Web Scanner UI"] -->|POST /api/scan/remote| Srv["ironclad-server (Go)"]
    Srv -->|vm/qfile + vm/qrender| RPC
    CLI -->|AST Analysis + SHA-256 Source & Report Hash| Report["Score 0..100 + Grade A+..F + SARIF 2.1.0"]
    Report -->|PublishAttestation tx| Realm["gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad"]
    Realm -->|Imports deterministic scorer & digest verifier| Pkg["gno.land/p/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad"]
    Researcher["Security Researcher"] -->|ChallengeAttestation(missedRuleID, evidence)| Realm
```

---

## Quick Start & Reproducible Verification

```bash
# 1. Test & lint Ironclad's own /p/ and /r/ Gno packages (v1.8.0-rc.1)
make gno-test
make gno-lint

# 2. Build CLI + Web Scanner & run Go unit tests (all 15 rules verified + cross-language digest check)
make build
make go-test

# 3. Scan any local Gno realm or live deployed onyx-1 package
./bin/ironclad scan --remote https://rpc.onyx.testnets.gno.land:443 gno.land/r/sys/namereg/v0
./bin/ironclad scan --format sarif --fail-on-high ./gno/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad

# 4. Run full live gnodev v1.8.0-rc.1 E2E test
#    (deploys /p/ -> /r/, live remote vm/qfile scan, PublishAttestation, web API digest verification, SARIF 2.1.0)
make e2e
```

---

## Live `onyx-1` Deployment

- **Pure Package:** `gno.land/p/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad`
- **Stateful Realm:** `gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad`
- **gnoweb Explorer:** `https://onyx.testnets.gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad`
- **GPAS Verification:** `https://gpas.onyx.testnets.gno.land/?path=gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad`
