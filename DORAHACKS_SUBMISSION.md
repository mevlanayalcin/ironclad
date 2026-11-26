# DoraHacks Submission — Ironclad (Gnome Tavern Hackathon)

- **Project Name:** Ironclad
- **Tagline (1 line):** Gno.land smart-contract static security analyzer (15 AST rules aligned with `gno-security.md` & PR `#5068`, SARIF v2.1.0, live `vm/qfile` scanning, deterministic WASM browser engine) + live `onyx-1` multi-auditor attestation registry.
- **GitHub Repository:** https://github.com/mevlanayalcin/ironclad
- **Live WebAssembly Browser Scanner:** https://mevlanayalcin.github.io/ironclad/
- **Live `onyx-1` Realm (`gnoweb`):** https://onyx.testnets.gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **Live `onyx-1` Pure Package:** https://onyx.testnets.gno.land/p/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **GPAS Verification (`passed`):** https://gpas.onyx.testnets.gno.land/?path=gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **HD Demo Video (1080p MP4, 2m25s):** https://github.com/mevlanayalcin/ironclad/releases/download/v1.0.0/ironclad-demo-1080p.mp4

## Live `onyx-1` On-Chain Proofs (`v1.8.0-rc.1`)
- **Deploy `/r/.../ironclad`:** Height `1420062` · TX `3XyOwZ87YyyiK7yu96GMcx1EPkkQI8NFwrCaZjp0DDY=` (GPAS `passed`)
- **`RegisterAuditor("IroncladCore")`:** Height `1421138` · TX `TjuV6XIsBo3+Q0UHT8yv7zqYwPmoXCOJbg1GG+CYUDQ=`
- **Attestation `#1` (`r/.../ironclad` — A+ 100/100):** Height `1421140` · TX `JleY8phTIKVyuEVuBnHK5IND1pWPRq7tdUtv9WAWRtI=`
- **Attestation `#2` (`r/sys/namereg/v0` — A 98/100):** Height `1421143` · TX `rTqnTFeb3Y0APyg4eBTFzMPK7JTVy7/XoeBA6CgdVsI=`
- **Attestation `#3` (`r/gnoland/wugnot` — A 94/100):** Height `1421145` · TX `8qmBi4kpsb14ufFnHTvKadEDSURSH9GWCwzfELjTr+U=`
- **Attestation `#4` (`r/gnoland/blog` — D 70/100):** Height `1421148` · TX `hgeu6JNeh6cIckc2LmcqwUth7Ni2C8bIHzQfCi0o/p4=`
- **Attestation `#5` (`r/sys/users` — D 55/100):** Height `1421151` · TX `2+rVt6yDZiyCXrQhWWspihDbE441UlO5kjxwzHMJ/NM=`
- **Attestation `#6` (`r/.../tollgate/v2` — A+ 100/100):** Height `1422326` · TX `Op88pR6njEhssKMgXjhZhGv+i6tiEB5zkKdHF8ylHno=`
- **`ChallengeAttestation(#4, AVL001)` + `RespondToChallenge(#1, rebutted)`:** Heights `1421555` (`gVMieVkF+JoBGB6HbjZtGPxw0TufJHFOEUtbL75mJVA=`) & `1421557` (`/8BmRYEdyJ4iukIy/iWFdsdPS2mjBumSZVjTkTNQNP0=`)
- **Deterministic WASM SHA-256 (`make build-wasm` on Go `1.24.6` with `-buildvcs=false -trimpath`):** `f87d697838b4079f738ee91c75b456ae199ac301d8bf7af53d33bc14d09b85b4`

## Problem & Innovation
In November 2026, Gno.land published its formal smart-contract security threat taxonomy (`docs/resources/gno-security.md`, `docs/resources/gno-ai-contract-review.md`) covering realm capability leaks (`Class-1a/1b`), designation forgery (`Class-2`), interface substitution & sealing bypasses (`Class-3`), closed-over callbacks (`Class-4`), `IsUser()` vs `IsUserCall()`, borrow-rule #2 pointer leaks, persisted bankers, `GetCoins()` gas DoS, unsanitized `Render(path)`, and lint rules `AVL001` / `GLOBAL001` / `RENDER001` (`#5068`).

**Ironclad** turns that entire specification into executable developer & ecosystem infrastructure:
1. **15 AST Security & Lint Rules + `PARSE-ERR`:** Line-preserving Gno preprocessor + `go/parser`/`go/ast` analyzer outputting Terminal, JSON, Markdown, and GitHub Code Scanning **SARIF v2.1.0**.
2. **Live Chain Scanning (`vm/qfile`):** Inspects any live deployed `onyx-1` package directly over RPC with zero local checkout required (`ironclad scan --remote https://rpc.onyx.testnets.gno.land:443 <pkgPath>`).
3. **Immutable Multi-Auditor Attestation & Challenge Registry (`r/.../ironclad`):** Pure `/p/` scoring & SHA-256 `AttestationDigest` verifier + stateful `/r/` realm indexed per `(pkgPath, auditor)` (preventing certificate hijacking and digest squatting) with structured `ChallengeAttestation` & `RespondToChallenge` auditor resolution.
4. **Deterministic WebAssembly Browser Scanner:** Live GitHub Pages UI (`https://mevlanayalcin.github.io/ironclad/`) runs the exact same Go AST engine compiled to reproducible `ironclad.wasm` directly in-browser via ABCI RPC and pure-Go WASM SHA-256.
