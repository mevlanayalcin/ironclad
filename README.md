# Ironclad — Gno Smart-Contract Static Security Analyzer & Multi-Auditor On-Chain Attestation Registry

> Built for the **Gno.land Gnome Tavern Hackathon (Nov–Dec 2026)** on Gno `v1.8.0-rc.1` (`onyx-1`).

**Ironclad** automates Gno.land's official November 2026 security specifications — **[`docs/resources/gno-security.md`](https://github.com/gnolang/gno/blob/master/docs/resources/gno-security.md)**, **[`docs/resources/gno-ai-contract-review.md`](https://github.com/gnolang/gno/blob/master/docs/resources/gno-ai-contract-review.md)**, and **[`gnolang/gno#5068`](https://github.com/gnolang/gno/pull/5068)** (`AVL001`, `GLOBAL001`, `RENDER001`) — pairing a calibrated Go AST static analyzer (CLI + SARIF v2.1.0 + **Go WebAssembly browser engine** with 1:1 CLI parity + live `vm/qfile` RPC scanning) with a **multi-auditor, content-addressed on-chain attestation & challenge-resolution registry** on `onyx-1`.

- **Live Browser Scanner (Go WASM + Direct `onyx-1` RPC):** https://mevlanayalcin.github.io/ironclad/
- **Live `onyx-1` Pure Package:** `gno.land/p/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad` (GPAS `passed`)
- **Live `onyx-1` Realm (`gnoweb`):** `https://onyx.testnets.gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad`

---

## Live `onyx-1` Calibration Walkthrough

Real scans executed directly against live `onyx-1` packages via ABCI `vm/qfile`:

```text
$ ironclad scan --remote https://rpc.onyx.testnets.gno.land:443 gno.land/r/sys/namereg/v0
Ironclad ironclad-1.0.0 | Target: gno.land/r/sys/namereg/v0
Grade: A (98/100) | Files: 9 | C:0 H:0 M:0 L:1 I:0
  [LOW] GNO-SEC01 (Class-2) users.gno:40 — crossing function Register checks IsUserCall() without explicit cur.IsCurrent() check

$ ironclad scan --remote https://rpc.onyx.testnets.gno.land:443 gno.land/r/gnoland/wugnot
Ironclad ironclad-1.0.0 | Target: gno.land/r/gnoland/wugnot
Grade: A (94/100) | Files: 1 | C:0 H:0 M:1 L:0 I:0
  [MEDIUM] GLOBAL001 (Lint-Encapsulation) wugnot.gno:16 — exported mutable global var Token exposes realm state directly

$ ironclad scan --remote https://rpc.onyx.testnets.gno.land:443 gno.land/r/gnoland/blog
Grade: D (70/100) | Files: 3 | C:1 H:0 M:0 L:0 I:0
  [CRITICAL] GNO-SEC01 (Class-2) admin.gno:46 — exported crossing function NewPostProposalRequest reads cur.Previous()/Address() without cur.IsCurrent() or AssertOriginCall()

$ ironclad scan --remote https://rpc.onyx.testnets.gno.land:443 gno.land/r/sys/users
Grade: D (55/100) | Files: 7 | C:0 H:3 M:0 L:0 I:0
  [HIGH] GNO-SEC03 (Write-Authority-Leak) users.gno:6 — exported function ResolveName returns pointer *UserData which may leak realm write authority via borrow rule #2
  [HIGH] GNO-SEC03 (Write-Authority-Leak) users.gno:21 — exported function ResolveAddress returns pointer *UserData which may leak realm write authority via borrow rule #2
  [HIGH] GNO-SEC03 (Write-Authority-Leak) users.gno:37 — exported function ResolveAny returns pointer *UserData which may leak realm write authority via borrow rule #2

$ ironclad scan --remote https://rpc.onyx.testnets.gno.land:443 gno.land/r/gov/dao
Grade: F (0/100) | Files: 2 | C:7 H:2 M:0 L:0 I:0
  [HIGH] GNO-SEC03 (Write-Authority-Leak) proxy.gno:117 — exported function MustGetProposal returns pointer *Proposal which may leak realm write authority via borrow rule #2
  [HIGH] GNO-SEC03 (Write-Authority-Leak) proxy.gno:129 — exported function GetProposal returns pointer *Proposal which may leak realm write authority via borrow rule #2
  [CRITICAL] GNO-TC1A (Class-1a) types.gno:158 — interface Executor declares method Execute accepting realm capability token

$ ironclad scan --pkg gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad ./gno/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
Ironclad ironclad-1.0.0 | Target: gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
Grade: A+ (100/100) | Files: 1 | C:0 H:0 M:0 L:0 I:0
Status         : PASS (0 security findings)
```

---

## Implemented Rules (15 Security & Lint Detectors + `PARSE-ERR`)

| Rule ID | Severity | Official Spec / Threat Class | What It Detects |
|---|---|---|---|
| `GNO-TC1A` | `CRITICAL` | Class-1a (`gno-security.md`) | Interface methods accepting `cur realm` (cur-disclosure / impersonate-self) |
| `GNO-TC1B` | `HIGH` | Class-1b (`gno-security.md`) | Passing live `cur realm` directly into caller-supplied callbacks `cb(cur)` or interface parameters |
| `GNO-TC2` | `CRITICAL` | Class-2 (`gno-security.md`) | Designation-forgery: caller-supplied `caller`/`sender`/`owner`/`admin` `address` or `callerPkgPath` args |
| `GNO-TC3` | `HIGH` | Class-3 (`gno-security.md`) | Unchecked open interfaces (`grc20.Teller`, `banker.Banker`, etc.) & bypassable unexported sealing markers (`isCanonical()`) |
| `GNO-TC4` | `HIGH` | Class-4 (`gno-security.md`) | Untrusted `func(...)` callbacks invoked under realm authority (exempts realm-owned `func(*MyState)` per §4) |
| `GNO-SEC01` | `CRITICAL`/`LOW` | Review Check #1 | Crossing function reading `cur.Previous()`/`cur.Address()` without `cur.IsCurrent()` or `AssertOriginCall()` |
| `GNO-SEC02` | `CRITICAL` | Review Check #2 | Payment handler checking `IsUser()` instead of `IsUserCall()`, or unguarded `unsafe.OriginSend()` |
| `GNO-SEC03` | `HIGH` | Review Checks #3 & #8 | Exported non-constructor returning mutable pointer (exempts `New*` and `*rotree.ReadOnlyTree`) |
| `GNO-SEC04` | `CRITICAL` | Review Check #6 & `banker.gno` | Persisting `realm` or `banker.Banker` capabilities in package-level globals |
| `GNO-SEC05` | `HIGH` | Review Check #9 | Using `unsafe.PreviousRealm()`/`CurrentRealm()`/`OriginCaller()` alongside `cur realm` |
| `GNO-SEC06` | `MEDIUM` | Review Check #10 | `Render(path)` concatenating dynamic strings without calling `markdown/sanitize/v0` |
| `GNO-SEC07` | `MEDIUM` | Review Check #11 | Unbounded `GetCoins(...).AmountOf(...)` or `GetCoins` in loops (unsolicited-denom gas DoS) |
| `AVL001` | `MEDIUM` | `gnolang/gno#5068` | Unbounded `avl.Tree.Iterate("", "", ...)` / `ReverseIterate` without limit/offset |
| `GLOBAL001` | `MEDIUM` | `gnolang/gno#5068` | Exported mutable global `var` in a `/r/` realm (exempts `Err* = errors.New(...)` sentinels) |
| `RENDER001` | `MEDIUM` | `gnolang/gno#5068` | State mutation (`=`, `++`, `.Set()`, `.Remove()`, `.SendCoins()`) inside `Render(path)` |
| `PARSE-ERR` | `HIGH` | Analysis Integrity | Unparsable `.gno` source file (prevents broken files from silently passing) |

Inline suppressions: append `//ironclad:ignore <RULE-ID>` on the line to document an intentional reviewed exception.

---

## Multi-Auditor On-Chain Trust Model (`r/.../ironclad`)

- **No Certificate Hijacking:** Attestations are indexed per `(targetPkgPath, auditor)` with full chronological history. `:pkg/<path>` displays multi-auditor consensus and lists every auditor's certificate separately.
- **No Digest Squatting:** Deduplication is scoped per `(digest, auditor)`; honest independent auditors can verify the same source snapshot without colliding.
- **Anti-Griefing Challenge Resolution:** `ChallengeAttestation` validates `missedRuleID` against the official taxonomy and tracks open challenges without letting anonymous callers flip an auditor's status; the original auditor resolves each challenge via `RespondToChallenge(challengeID, accept, rationale)` (accepting auto-revokes with audit trail; rebutting records the public rationale).
- **Hardened Rendering & JSON:** Overflow-capped finding counts (`0..100000`), strict `[A-Z0-9,-]` rule tokens, unique auditor handles, paginated listings, and Markdown-safe unicode escaping (`\u005b` etc.) in `:json/*`.

---

## Known Limitations
- Ironclad performs syntactic & intra-package AST analysis without full cross-package type inference; complex aliased pointer leaks across multiple `/p/` indirections still require manual review.
- On-chain attestations are auditor-signed, self-reported claims bound to `(pkgPath, sourceHash, reportDigest)`; consumers should verify auditor identity and recompute the digest via CLI or WASM.

---

## Quick Start

```bash
make gno-test && make gno-lint   # Gno v1.8.0-rc.1 unit tests & lint
make build && make go-test       # Go CLI, SSRF-hardened server, WASM engine & race tests
make e2e                         # Full live gnodev v1.8.0-rc.1 E2E test + SARIF 2.1.0 check
```

---

## Live `onyx-1` Deployment & HD Demo Video

- **HD Demo Video (1080p MP4):** [Watch / Download `ironclad-demo-1080p.mp4`](https://github.com/mevlanayalcin/ironclad/releases/download/v1.0.0/ironclad-demo-1080p.mp4)
- **Live `onyx-1` Realm (`gnoweb`):** https://onyx.testnets.gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **Live WebAssembly Browser Scanner:** https://mevlanayalcin.github.io/ironclad/
- **GPAS Verification (`passed`):** https://gpas.onyx.testnets.gno.land/?path=gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **Reproducible WASM SHA-256 (`make build-wasm`):** `f87d697838b4079f738ee91c75b456ae199ac301d8bf7af53d33bc14d09b85b4`
- **Live On-Chain Proofs:** Deploy TX `3XyOwZ87YyyiK7yu96GMcx1EPkkQI8NFwrCaZjp0DDY=` (`1420062`), `RegisterAuditor` TX `TjuV6XIsBo3+Q0UHT8yv7zqYwPmoXCOJbg1GG+CYUDQ=` (`1421138`), plus 5 live `PublishAttestation` records (`r/.../ironclad` A+, `r/sys/namereg/v0` A, `r/gnoland/wugnot` A, `r/gnoland/blog` D, `r/sys/users` D).
