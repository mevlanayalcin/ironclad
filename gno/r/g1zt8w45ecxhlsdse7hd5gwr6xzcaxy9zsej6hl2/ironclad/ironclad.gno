// Package ironclad implements an immutable, content-addressed on-chain audit
// attestation and security badge registry for Gno.land packages and realms.
// Every function strictly complies with gno-security.md and gno-ai-contract-review.md.
package ironclad

import (
	"chain"
	"chain/runtime"
	"strconv"
	"strings"

	pironclad "gno.land/p/g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2/ironclad"
	"gno.land/p/nt/avl/v0"
	"gno.land/p/nt/markdown/sanitize/v0"
	"gno.land/p/nt/seqid/v0"
	"gno.land/p/nt/ufmt/v0"
)

const (
	StatusValid      = "valid"
	StatusChallenged = "challenged"
	StatusRevoked    = "revoked"

	maxRenderRows = 25
	maxHandleLen  = 40
	maxBioLen     = 240
	maxSummaryLen = 400
	maxRulesLen   = 240
	maxURLLen     = 200
)

type auditorRecord struct {
	addr              address
	handle            string
	bio               string
	websiteURL        string
	registeredHeight  int64
	attestationsCount int64
	revocationsCount  int64
}

type attestationRecord struct {
	id              uint64
	auditor         address
	targetPkgPath   string
	sourceHash      string
	reportDigest    string
	digest          string
	analyzerVersion string
	critical        int
	high            int
	medium          int
	low             int
	info            int
	score           int
	grade           string
	rulesTriggered  string
	summary         string
	reportURL       string
	height          int64
	status          string
	revokeReason    string
	challengeCount  int
}

type challengeRecord struct {
	id             uint64
	attestationID  uint64
	challenger     address
	missedRuleID   string
	evidenceDigest string
	reason         string
	height         int64
}

// Public read-only value views (zero mutable pointers ever returned).

type AuditorView struct {
	Addr              address
	Handle            string
	Bio               string
	WebsiteURL        string
	RegisteredHeight  int64
	AttestationsCount int64
	RevocationsCount  int64
}

type AttestationView struct {
	ID              uint64
	Auditor         address
	TargetPkgPath   string
	SourceHash      string
	ReportDigest    string
	Digest          string
	AnalyzerVersion string
	Critical        int
	High            int
	Medium          int
	Low             int
	Info            int
	Score           int
	Grade           string
	RulesTriggered  string
	Summary         string
	ReportURL       string
	Height          int64
	Status          string
	RevokeReason    string
	ChallengeCount  int
}

// Strictly unexported realm state (zero GLOBAL001 violations).
var (
	auditors       = avl.NewTree()
	attestations   = avl.NewTree()
	latestByPkg    = avl.NewTree()
	digestIndex    = avl.NewTree()
	challenges     = avl.NewTree()
	nextAttestID   seqid.ID
	nextChallengID seqid.ID
)

func mustCurrent(cur realm) {
	if !cur.IsCurrent() {
		panic("ironclad: spoofed realm capability")
	}
}

func getAttestationRecord(id uint64) *attestationRecord {
	if id == 0 {
		return nil
	}
	v := attestations.Get(seqid.ID(id).Binary())
	if v == nil {
		return nil
	}
	return v.(*attestationRecord)
}

func getAuditorRecord(addr address) *auditorRecord {
	v := auditors.Get(addr.String())
	if v == nil {
		return nil
	}
	return v.(*auditorRecord)
}

// RegisterAuditor creates or updates the caller's on-chain auditor profile.
func RegisterAuditor(cur realm, handle, bio, websiteURL string) {
	mustCurrent(cur)
	caller := cur.Previous().Address()

	handle = strings.TrimSpace(sanitize.StripBidiAndZeroWidth(handle))
	if handle == "" || len(handle) > maxHandleLen {
		panic("ironclad: invalid handle")
	}
	bio = strings.TrimSpace(sanitize.StripBidiAndZeroWidth(bio))
	if len(bio) > maxBioLen {
		panic("ironclad: bio exceeds max length")
	}
	cleanURL := ""
	if strings.TrimSpace(websiteURL) != "" {
		cleanURL = sanitize.URL(strings.TrimSpace(websiteURL))
		if cleanURL == "" || len(cleanURL) > maxURLLen {
			panic("ironclad: invalid website URL")
		}
	}

	existing := getAuditorRecord(caller)
	if existing == nil {
		auditors.Set(caller.String(), &auditorRecord{
			addr:             caller,
			handle:           handle,
			bio:              bio,
			websiteURL:       cleanURL,
			registeredHeight: runtime.ChainHeight(),
		})
	} else {
		existing.handle = handle
		existing.bio = bio
		existing.websiteURL = cleanURL
	}
	chain.Emit("AuditorRegistered", "auditor", caller.String(), "handle", handle)
}

// PublishAttestation anchors an immutable, content-addressed static security
// analysis verdict for a Gno package/realm snapshot on chain.
func PublishAttestation(
	cur realm,
	targetPkgPath string,
	sourceHash string,
	reportDigest string,
	analyzerVersion string,
	critical int,
	high int,
	medium int,
	low int,
	info int,
	rulesTriggered string,
	summary string,
	reportURL string,
) uint64 {
	mustCurrent(cur)
	caller := cur.Previous().Address()

	targetPkgPath = strings.TrimSpace(targetPkgPath)
	if !pironclad.ValidatePkgPath(targetPkgPath) {
		panic("ironclad: invalid targetPkgPath (must start with gno.land/r/ or gno.land/p/)")
	}
	if !pironclad.IsValidHexDigest(sourceHash) {
		panic("ironclad: invalid sourceHash (expect 64-char lowercase sha256 hex)")
	}
	if !pironclad.IsValidHexDigest(reportDigest) {
		panic("ironclad: invalid reportDigest (expect 64-char lowercase sha256 hex)")
	}
	analyzerVersion = strings.TrimSpace(sanitize.StripBidiAndZeroWidth(analyzerVersion))
	if analyzerVersion == "" || len(analyzerVersion) > 48 {
		panic("ironclad: invalid analyzerVersion")
	}
	if critical < 0 || high < 0 || medium < 0 || low < 0 || info < 0 {
		panic("ironclad: finding counts cannot be negative")
	}
	rulesTriggered = strings.TrimSpace(sanitize.StripBidiAndZeroWidth(rulesTriggered))
	if len(rulesTriggered) > maxRulesLen {
		panic("ironclad: rulesTriggered exceeds max length")
	}
	summary = strings.TrimSpace(sanitize.StripBidiAndZeroWidth(summary))
	if len(summary) > maxSummaryLen {
		panic("ironclad: summary exceeds max length")
	}
	cleanURL := ""
	if strings.TrimSpace(reportURL) != "" {
		cleanURL = sanitize.URL(strings.TrimSpace(reportURL))
		if cleanURL == "" || len(cleanURL) > maxURLLen {
			panic("ironclad: invalid reportURL")
		}
	}

	score := pironclad.ComputeScore(critical, high, medium, low)
	grade := pironclad.ComputeGrade(score, critical, high)
	digest := pironclad.AttestationDigest(
		runtime.ChainID(),
		targetPkgPath,
		sourceHash,
		reportDigest,
		analyzerVersion,
		critical, high, medium, low, info,
	)
	if digestIndex.Has(digest) {
		panic("ironclad: identical attestation already published")
	}

	aid := nextAttestID.Next()
	rec := &attestationRecord{
		id:              uint64(aid),
		auditor:         caller,
		targetPkgPath:   targetPkgPath,
		sourceHash:      sourceHash,
		reportDigest:    reportDigest,
		digest:          digest,
		analyzerVersion: analyzerVersion,
		critical:        critical,
		high:            high,
		medium:          medium,
		low:             low,
		info:            info,
		score:           score,
		grade:           grade,
		rulesTriggered:  rulesTriggered,
		summary:         summary,
		reportURL:       cleanURL,
		height:          runtime.ChainHeight(),
		status:          StatusValid,
	}
	attestations.Set(aid.Binary(), rec)
	latestByPkg.Set(targetPkgPath, rec.id)
	digestIndex.Set(digest, rec.id)

	if aud := getAuditorRecord(caller); aud != nil {
		aud.attestationsCount++
	} else {
		auditors.Set(caller.String(), &auditorRecord{
			addr:              caller,
			handle:            "auditor-" + caller.String()[:10],
			registeredHeight:  runtime.ChainHeight(),
			attestationsCount: 1,
		})
	}

	chain.Emit(
		"AttestationPublished",
		"attestation_id", strconv.FormatUint(rec.id, 10),
		"target_pkg", targetPkgPath,
		"auditor", caller.String(),
		"score", strconv.Itoa(score),
		"grade", grade,
		"digest", digest,
	)
	return rec.id
}

// ChallengeAttestation records an on-chain counter-finding against a published
// attestation, flagging a missed rule ID and evidence SHA-256 hash.
func ChallengeAttestation(
	cur realm,
	attestationID uint64,
	missedRuleID string,
	evidenceDigest string,
	reason string,
) uint64 {
	mustCurrent(cur)
	rec := getAttestationRecord(attestationID)
	if rec == nil {
		panic("ironclad: attestation not found")
	}
	if rec.status == StatusRevoked {
		panic("ironclad: attestation already revoked")
	}
	missedRuleID = strings.TrimSpace(sanitize.StripBidiAndZeroWidth(missedRuleID))
	if missedRuleID == "" || len(missedRuleID) > 32 {
		panic("ironclad: invalid missedRuleID")
	}
	if !pironclad.IsValidHexDigest(evidenceDigest) {
		panic("ironclad: invalid evidenceDigest")
	}
	reason = strings.TrimSpace(sanitize.StripBidiAndZeroWidth(reason))
	if reason == "" || len(reason) > maxSummaryLen {
		panic("ironclad: valid challenge reason required")
	}

	cid := nextChallengID.Next()
	ch := &challengeRecord{
		id:             uint64(cid),
		attestationID:  attestationID,
		challenger:     cur.Previous().Address(),
		missedRuleID:   missedRuleID,
		evidenceDigest: evidenceDigest,
		reason:         reason,
		height:         runtime.ChainHeight(),
	}
	challenges.Set(cid.Binary(), ch)
	rec.challengeCount++
	rec.status = StatusChallenged

	chain.Emit(
		"AttestationChallenged",
		"challenge_id", strconv.FormatUint(ch.id, 10),
		"attestation_id", strconv.FormatUint(attestationID, 10),
		"rule_id", missedRuleID,
		"challenger", ch.challenger.String(),
	)
	return ch.id
}

// RevokeAttestation lets the original auditor mark an attestation as revoked.
func RevokeAttestation(cur realm, attestationID uint64, reason string) {
	mustCurrent(cur)
	rec := getAttestationRecord(attestationID)
	if rec == nil {
		panic("ironclad: attestation not found")
	}
	caller := cur.Previous().Address()
	if caller != rec.auditor {
		panic("ironclad: only original auditor may revoke attestation")
	}
	if rec.status == StatusRevoked {
		panic("ironclad: already revoked")
	}
	reason = strings.TrimSpace(sanitize.StripBidiAndZeroWidth(reason))
	if reason == "" || len(reason) > maxSummaryLen {
		panic("ironclad: revocation reason required")
	}
	rec.status = StatusRevoked
	rec.revokeReason = reason
	if aud := getAuditorRecord(caller); aud != nil {
		aud.revocationsCount++
	}
	chain.Emit("AttestationRevoked", "attestation_id", strconv.FormatUint(attestationID, 10), "auditor", caller.String())
}

// --- Read-only value getters ---

func GetAttestation(id uint64) (AttestationView, bool) {
	r := getAttestationRecord(id)
	if r == nil {
		return AttestationView{}, false
	}
	return AttestationView{
		ID:              r.id,
		Auditor:         r.auditor,
		TargetPkgPath:   r.targetPkgPath,
		SourceHash:      r.sourceHash,
		ReportDigest:    r.reportDigest,
		Digest:          r.digest,
		AnalyzerVersion: r.analyzerVersion,
		Critical:        r.critical,
		High:            r.high,
		Medium:          r.medium,
		Low:             r.low,
		Info:            r.info,
		Score:           r.score,
		Grade:           r.grade,
		RulesTriggered:  r.rulesTriggered,
		Summary:         r.summary,
		ReportURL:       r.reportURL,
		Height:          r.height,
		Status:          r.status,
		RevokeReason:    r.revokeReason,
		ChallengeCount:  r.challengeCount,
	}, true
}

func GetLatestForPackage(targetPkgPath string) (AttestationView, bool) {
	v := latestByPkg.Get(targetPkgPath)
	if v == nil {
		return AttestationView{}, false
	}
	return GetAttestation(v.(uint64))
}

func VerifyAttestationByDigest(digest string) (uint64, bool) {
	if !pironclad.IsValidHexDigest(digest) {
		return 0, false
	}
	v := digestIndex.Get(digest)
	if v == nil {
		return 0, false
	}
	return v.(uint64), true
}

func GetAuditor(addr address) (AuditorView, bool) {
	a := getAuditorRecord(addr)
	if a == nil {
		return AuditorView{}, false
	}
	return AuditorView{
		Addr:              a.addr,
		Handle:            a.handle,
		Bio:               a.bio,
		WebsiteURL:        a.websiteURL,
		RegisteredHeight:  a.registeredHeight,
		AttestationsCount: a.attestationsCount,
		RevocationsCount:  a.revocationsCount,
	}, true
}

// --- Pure read-only gnoweb Markdown + JSON Renderer ---

func jsonEscape(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(" ")
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func Render(path string) string {
	path = strings.Trim(path, "/")
	if path == "" {
		return renderHome()
	}
	if path == "taxonomy" {
		return renderTaxonomy()
	}
	if path == "auditors" {
		return renderAuditors()
	}
	if strings.HasPrefix(path, "attestation/") {
		return renderAttestationDetail(strings.TrimPrefix(path, "attestation/"))
	}
	if strings.HasPrefix(path, "pkg/") {
		return renderPackageDetail(strings.TrimPrefix(path, "pkg/"))
	}
	if strings.HasPrefix(path, "json/") {
		return renderJSON(strings.TrimPrefix(path, "json/"))
	}
	return "# Ironclad — Not Found\n\nUnknown path " + sanitize.InlineCode(path) + ".\n\n[Back to Home](:)\n"
}

func renderHome() string {
	var b strings.Builder
	b.WriteString("# Ironclad — Gno Smart-Contract Security Attestation Registry\n\n")
	b.WriteString("> Content-addressed on-chain audit certificates implementing Gno.land's official November 2026 Threat-Class Taxonomy (`gno-security.md`, `gno-ai-contract-review.md`, `AVL001`, `GLOBAL001`, `RENDER001`).\n\n")

	b.WriteString("## Registry Telemetry\n\n")
	b.WriteString("| Metric | Value |\n|---|---|\n")
	b.WriteString(ufmt.Sprintf("| Chain ID | `%s` |\n", sanitize.InlineText(runtime.ChainID())))
	b.WriteString(ufmt.Sprintf("| Block Height | `%d` |\n", runtime.ChainHeight()))
	b.WriteString(ufmt.Sprintf("| Total Attestations | `%d` |\n", attestations.Size()))
	b.WriteString(ufmt.Sprintf("| Distinct Attested Packages | `%d` |\n", latestByPkg.Size()))
	b.WriteString(ufmt.Sprintf("| Registered Auditors | `%d` |\n", auditors.Size()))
	b.WriteString(ufmt.Sprintf("| On-Chain Challenges | `%d` |\n\n", challenges.Size()))

	b.WriteString("## Recent Security Attestations\n\n")
	if attestations.Size() == 0 {
		b.WriteString("_No audit attestations published yet._\n\n")
	} else {
		b.WriteString("| ID | Package | Grade | Score | Findings (C/H/M/L) | Status | Source Hash |\n|---|---|---|---|---|---|---|\n")
		attestations.ReverseIterateByOffset(0, maxRenderRows, func(_ string, v any) bool {
			r := v.(*attestationRecord)
			shortSrc := r.sourceHash
			if len(shortSrc) > 12 {
				shortSrc = shortSrc[:12] + "..."
			}
			b.WriteString(ufmt.Sprintf(
				"| [%d](:attestation/%d) | [`%s`](:pkg/%s) | **%s** | `%d/100` | `%d/%d/%d/%d` | `%s` | `%s` |\n",
				r.id, r.id,
				sanitize.TableCell(r.targetPkgPath),
				sanitize.URL(r.targetPkgPath),
				sanitize.TableCell(r.grade),
				r.score,
				r.critical, r.high, r.medium, r.low,
				sanitize.TableCell(r.status),
				sanitize.TableCell(shortSrc),
			))
			return false
		})
		b.WriteString("\n")
	}

	b.WriteString("## Navigation\n\n")
	b.WriteString("- [Threat-Class Taxonomy (14 Rules)](:taxonomy)\n")
	b.WriteString("- [Auditor Directory](:auditors)\n")
	b.WriteString("- Machine JSON: `:json/summary`, `:json/attestations`, `:json/pkg/<pkgPath>`, `:json/attestation/<id>`\n")
	return b.String()
}

func renderTaxonomy() string {
	var b strings.Builder
	b.WriteString("# Ironclad — Official Gno Security Threat-Class Taxonomy\n\n[Back to Home](:)\n\n")
	b.WriteString("| Rule ID | Severity | Threat Class | Reference | Remediation |\n|---|---|---|---|---|\n")
	for _, tc := range pironclad.Taxonomy() {
		b.WriteString(ufmt.Sprintf(
			"| `%s` | `%s` | %s | `%s` | %s |\n",
			tc.Code, tc.Severity, tc.Title, tc.Reference, tc.Remediation,
		))
	}
	return b.String()
}

func renderAuditors() string {
	var b strings.Builder
	b.WriteString("# Ironclad — Registered Auditors\n\n[Back to Home](:)\n\n")
	if auditors.Size() == 0 {
		b.WriteString("_No auditors registered yet._\n")
		return b.String()
	}
	b.WriteString("| Handle | Address | Attestations | Revocations | Bio |\n|---|---|---|---|---|\n")
	auditors.ReverseIterateByOffset(0, maxRenderRows, func(_ string, v any) bool {
		a := v.(*auditorRecord)
		b.WriteString(ufmt.Sprintf(
			"| **%s** | `%s` | `%d` | `%d` | %s |\n",
			sanitize.TableCell(a.handle), a.addr.String(), a.attestationsCount, a.revocationsCount, sanitize.TableCell(a.bio),
		))
		return false
	})
	return b.String()
}

func renderPackageDetail(pkgPath string) string {
	att, ok := GetLatestForPackage(pkgPath)
	if !ok {
		return "# Package Not Attested\n\nNo Ironclad audit attestation exists for " + sanitize.InlineCode(pkgPath) + ".\n\n[Back to Home](:)\n"
	}
	var b strings.Builder
	b.WriteString("# Security Certificate: " + sanitize.InlineCode(att.TargetPkgPath) + "\n\n")
	b.WriteString("[Back to Home](:) | [Full Attestation #" + strconv.FormatUint(att.ID, 10) + "](:attestation/" + strconv.FormatUint(att.ID, 10) + ")\n\n")
	b.WriteString(ufmt.Sprintf("> **Ironclad Grade: `%s` (`%d / 100`)** — Status: `%s` — Analyzer: `%s`\n\n",
		sanitize.InlineText(att.Grade), att.Score, sanitize.InlineText(att.Status), sanitize.InlineText(att.AnalyzerVersion)))
	if att.Summary != "" {
		b.WriteString(sanitize.Block(att.Summary))
	}
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Auditor | `" + att.Auditor.String() + "` |\n")
	b.WriteString("| Source SHA-256 | `" + sanitize.TableCell(att.SourceHash) + "` |\n")
	b.WriteString("| Report Digest | `" + sanitize.TableCell(att.ReportDigest) + "` |\n")
	b.WriteString("| On-Chain Commitment | `" + sanitize.TableCell(att.Digest) + "` |\n")
	b.WriteString(ufmt.Sprintf("| Findings | Critical `%d` · High `%d` · Medium `%d` · Low `%d` · Info `%d` |\n",
		att.Critical, att.High, att.Medium, att.Low, att.Info))
	if att.RulesTriggered != "" {
		b.WriteString("| Rules Triggered | " + sanitize.InlineCode(att.RulesTriggered) + " |\n")
	}
	b.WriteString(ufmt.Sprintf("| Challenges | `%d` |\n", att.ChallengeCount))
	b.WriteString(ufmt.Sprintf("| Block Height | `%d` |\n", att.Height))
	return b.String()
}

func renderAttestationDetail(rawID string) string {
	id, err := strconv.ParseUint(rawID, 10, 64)
	if err != nil {
		if aid, ok := VerifyAttestationByDigest(rawID); ok {
			id = aid
		} else {
			return "# Attestation Not Found\n\nUnknown attestation " + sanitize.InlineCode(rawID) + ".\n"
		}
	}
	att, ok := GetAttestation(id)
	if !ok {
		return "# Attestation Not Found\n"
	}
	return renderPackageDetail(att.TargetPkgPath)
}

func attestationJSON(r *attestationRecord) string {
	return ufmt.Sprintf(
		`{"id":%d,"auditor":%s,"targetPkgPath":%s,"sourceHash":%s,"reportDigest":%s,"digest":%s,"analyzerVersion":%s,"critical":%d,"high":%d,"medium":%d,"low":%d,"info":%d,"score":%d,"grade":%s,"rulesTriggered":%s,"summary":%s,"reportUrl":%s,"height":%d,"status":%s,"revokeReason":%s,"challengeCount":%d}`,
		r.id, jsonEscape(r.auditor.String()), jsonEscape(r.targetPkgPath), jsonEscape(r.sourceHash),
		jsonEscape(r.reportDigest), jsonEscape(r.digest), jsonEscape(r.analyzerVersion),
		r.critical, r.high, r.medium, r.low, r.info, r.score, jsonEscape(r.grade),
		jsonEscape(r.rulesTriggered), jsonEscape(r.summary), jsonEscape(r.reportURL),
		r.height, jsonEscape(r.status), jsonEscape(r.revokeReason), r.challengeCount,
	)
}

func renderJSON(sub string) string {
	if sub == "summary" {
		return ufmt.Sprintf(
			`{"protocol":%s,"chainId":%s,"height":%d,"attestations":%d,"packages":%d,"auditors":%d,"challenges":%d}`,
			jsonEscape(pironclad.ProtocolVersion),
			jsonEscape(runtime.ChainID()),
			runtime.ChainHeight(),
			attestations.Size(),
			latestByPkg.Size(),
			auditors.Size(),
			challenges.Size(),
		)
	}
	if sub == "attestations" {
		var b strings.Builder
		b.WriteByte('[')
		first := true
		attestations.ReverseIterateByOffset(0, maxRenderRows, func(_ string, v any) bool {
			if !first {
				b.WriteByte(',')
			}
			first = false
			b.WriteString(attestationJSON(v.(*attestationRecord)))
			return false
		})
		b.WriteByte(']')
		return b.String()
	}
	if strings.HasPrefix(sub, "pkg/") {
		pkgPath := strings.TrimPrefix(sub, "pkg/")
		if v := latestByPkg.Get(pkgPath); v != nil {
			if r := getAttestationRecord(v.(uint64)); r != nil {
				return attestationJSON(r)
			}
		}
		return `{"error":"not_found"}`
	}
	if strings.HasPrefix(sub, "attestation/") {
		raw := strings.TrimPrefix(sub, "attestation/")
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			if aid, ok := VerifyAttestationByDigest(raw); ok {
				id = aid
			}
		}
		if r := getAttestationRecord(id); r != nil {
			return attestationJSON(r)
		}
		return `{"error":"not_found"}`
	}
	return `{"error":"not_found"}`
}
