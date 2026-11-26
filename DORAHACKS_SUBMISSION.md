# DoraHacks Submission — Ironclad (Gnome Tavern Hackathon)

- **Project Name:** Ironclad
- **Tagline (1 line):** Gno.land smart-contract static security analyzer (15 AST rules aligned with `gno-security.md` & PR `#5068`, SARIF v2.1.0, `ironclad mcp`, GitHub Action `action.yml`, deterministic WASM + Adena Wallet) + live `onyx-1` multi-auditor attestation registry (12 verified live packages).
- **GitHub Repository:** https://github.com/mevlanayalcin/ironclad
- **Live WebAssembly Browser Suite (Adena Wallet + 12/12 WASM Verifier + Exploit/Patch Lab):** https://mevlanayalcin.github.io/ironclad/
- **Live `onyx-1` Realm (`gnoweb`):** https://onyx.testnets.gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **Live `onyx-1` Pure Package:** https://onyx.testnets.gno.land/p/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **GPAS Verification (`passed`):** https://gpas.onyx.testnets.gno.land/?path=gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **HD Demo Video (1080p MP4):** https://mevlanayalcin.github.io/ironclad/ironclad-demo-1080p.mp4 (also attached on GitHub Releases `v1.0.0`)

## Live `onyx-1` On-Chain Proofs (`v1.8.0-rc.1` — 12 Attestations · 12 Packages · 1 Auditor · 1 Resolved Challenge)
- **Deploy `/r/.../ironclad`:** Height `1420062` · TX `3XyOwZ87YyyiK7yu96GMcx1EPkkQI8NFwrCaZjp0DDY=` (GPAS `passed`)
- **`RegisterAuditor("IroncladCore")`:** Height `1421138` · TX `TjuV6XIsBo3+Q0UHT8yv7zqYwPmoXCOJbg1GG+CYUDQ=`
- **Attestation `#1` (`r/.../ironclad` — A+ 100/100):** Height `1421140` · TX `JleY8phTIKVyuEVuBnHK5IND1pWPRq7tdUtv9WAWRtI=`
- **Attestation `#2` (`r/sys/namereg/v0` — A 98/100):** Height `1421143` · TX `rTqnTFeb3Y0APyg4eBTFzMPK7JTVy7/XoeBA6CgdVsI=`
- **Attestation `#3` (`r/gnoland/wugnot` — A 94/100):** Height `1421145` · TX `8qmBi4kpsb14ufFnHTvKadEDSURSH9GWCwzfELjTr+U=`
- **Attestation `#4` (`r/gnoland/blog` — D 70/100):** Height `1421148` · TX `hgeu6JNeh6cIckc2LmcqwUth7Ni2C8bIHzQfCi0o/p4=`
- **Attestation `#5` (`r/sys/users` — D 55/100):** Height `1421151` · TX `2+rVt6yDZiyCXrQhWWspihDbE441UlO5kjxwzHMJ/NM=`
- **Attestation `#6` (`r/.../tollgate/v2` — A+ 100/100):** Height `1422326` · TX `Op88pR6njEhssKMgXjhZhGv+i6tiEB5zkKdHF8ylHno=`
- **Attestation `#7` (`r/gov/dao` — F 0/100, C:7 H:2):** Height `1430407` · TX `0yh7YVFczXrCvjhf2KoC46LilBNcvNscLPjQYzGe2Ic=`
- **Attestation `#8` (`r/sys/params` — A 94/100, M:1):** Height `1430416` · TX `MfhJKmgtM7CawgDMAYOwwcEc7PTMj03Uvefj///zAMk=`
- **Attestation `#9` (`r/sys/validators/v2` — B 85/100, H:1):** Height `1430418` · TX `gfLsF44jXKImzziuX7DP+Lfb+OiSq6DRsUzsscB5Ehc=`
- **Attestation `#10` (`r/gnoland/boards2/v0` — F 0/100, C:25 H:1 M:4):** Height `1430429` · TX `/btsZuLgKs72tZuwvtmu/rsWTqRCJ1qBFX82xRWuuhw=`
- **Attestation `#11` (`r/gnoland/coins` — A+ 100/100):** Height `1430431` · TX `gQVwCD0QK4rMnGUmadbjvaCieglJjyrqVH96ErDVr+Q=`
- **Attestation `#12` (`r/sys/rewards` — A+ 100/100):** Height `1430433` · TX `u53+auadHSS4LPRWXNL6aEz/T3zLEotn5NlUmVmxkUY=`
- **`ChallengeAttestation(#4, AVL001)` + `RespondToChallenge(#1, rebutted)`:** Heights `1421555` (`gVMieVkF+JoBGB6HbjZtGPxw0TufJHFOEUtbL75mJVA=`) & `1421557` (`/8BmRYEdyJ4iukIy/iWFdsdPS2mjBumSZVjTkTNQNP0=`)
- **Deterministic WASM SHA-256 (`make build-wasm` on Go `1.24.6` with `-buildvcs=false -trimpath`):** `f87d697838b4079f738ee91c75b456ae199ac301d8bf7af53d33bc14d09b85b4`

## Problem & Innovation
In November 2026, Gno.land published its formal smart-contract security threat taxonomy (`docs/resources/gno-security.md`, `docs/resources/gno-ai-contract-review.md`) covering realm capability leaks (`Class-1a/1b`), designation forgery (`Class-2`), interface substitution & sealing bypasses (`Class-3`), closed-over callbacks (`Class-4`), `IsUser()` vs `IsUserCall()`, borrow-rule #2 pointer leaks, persisted bankers, `GetCoins()` gas DoS, unsanitized `Render(path)`, and lint rules `AVL001` / `GLOBAL001` / `RENDER001` (`#5068`).

**Ironclad** turns that entire specification into executable developer & ecosystem infrastructure:
1. **15 AST Security & Lint Rules + `PARSE-ERR`:** Line-preserving Gno preprocessor + `go/parser`/`go/ast` analyzer outputting Terminal, JSON, Markdown, and GitHub Code Scanning **SARIF v2.1.0**, packaged as a CLI and drop-in **GitHub Action (`action.yml`)**.
2. **Native MCP Server (`ironclad mcp`) & Live Chain Scanning (`vm/qfile`):** Inspects any live deployed `onyx-1` package directly over RPC (`ironclad scan --remote ...`) and exposes 4 MCP JSON-RPC 2.0 tools (`ironclad_scan_source`, `ironclad_scan_remote`, `ironclad_verify_attestation`, `ironclad_list_rules`) for AI coding agents.
3. **Immutable Multi-Auditor Attestation & Challenge Registry (`r/.../ironclad`):** Pure `/p/` scoring & SHA-256 `AttestationDigest` verifier + stateful `/r/` realm indexed per `(pkgPath, auditor)` (preventing certificate hijacking and digest squatting) with structured `ChallengeAttestation` & `RespondToChallenge` auditor resolution — seeded with **12 verified live `onyx-1` packages** spanning A+ to F.
4. **Trustless Browser WASM Verifier, Adena Wallet & Interactive Exploit/Patch Lab:** Live GitHub Pages suite (`https://mevlanayalcin.github.io/ironclad/`) runs reproducible `ironclad.wasm` directly in-browser to independently re-verify all 12 on-chain attestations bit-for-bit, supports 1-click **Adena Wallet** `RegisterAuditor` / `PublishAttestation` / `ChallengeAttestation`, exports SARIF v2.1.0, and includes a 6-scenario Threat-Class Exploit & 1-Click Safe-Patch sandbox.
