# DoraHacks Submission — Ironclad (Gnome Tavern Hackathon)

- **Project Name:** Ironclad
- **Tagline (1 line):** Gno.land smart-contract static security analyzer (15 AST rules aligned with `gno-security.md` & PR `#5068`, SARIF v2.1.0, live `vm/qfile` scanning) + on-chain audit attestation registry.
- **GitHub Repository:** https://github.com/mevlanayalcin/ironclad
- **Live Web Security Scanner:** https://mevlanayalcin.github.io/ironclad/
- **Live `onyx-1` Realm (`gnoweb`):** https://onyx.testnets.gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **Live `onyx-1` Pure Package:** https://onyx.testnets.gno.land/p/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **GPAS Verification:** https://gpas.onyx.testnets.gno.land/?path=gno.land/r/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad
- **Demo Video URL:** _(updated automatically on final release upload)_

## Problem & Innovation
In November 2026, Gno.land published its formal smart-contract security threat taxonomy (`docs/resources/gno-security.md`, `docs/resources/gno-ai-contract-review.md`) covering realm capability leaks (`Class-1a/1b`), designation forgery (`Class-2`), interface substitution & sealing bypasses (`Class-3`), closed-over callbacks (`Class-4`), `IsUser()` vs `IsUserCall()`, borrow-rule #2 pointer leaks, persisted bankers, `GetCoins()` gas DoS, unsanitized `Render(path)`, and lint rules `AVL001` / `GLOBAL001` / `RENDER001` (`#5068`).

**Ironclad** turns that entire specification into executable developer & ecosystem infrastructure:
1. **15 AST Security & Lint Rules:** Line-preserving Gno preprocessor + `go/parser`/`go/ast` analyzer outputting Terminal, JSON, Markdown, and GitHub Code Scanning **SARIF v2.1.0**.
2. **Live Chain Scanning (`vm/qfile`):** Inspects any live deployed `onyx-1` package directly over RPC with zero local checkout required.
3. **Immutable On-Chain Attestation & Challenge Registry (`r/.../ironclad`):** Pure `/p/` scoring & SHA-256 `AttestationDigest` verifier + stateful `/r/` realm where auditors publish content-addressed certificates (`A+`..`F`) bound to exact `(pkgPath, sourceHash, reportDigest)` and security researchers can challenge missed findings on-chain.
4. **Standalone Browser Scanner:** Live GitHub Pages UI scans pasted `.gno` contracts or live `onyx-1` realms directly in-browser via ABCI RPC + WebCrypto.
