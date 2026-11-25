package ironclad

import (
	"strings"
	"testing"

	"gno.land/p/nt/avl/v0"
	"gno.land/p/nt/testutils/v0"
	"gno.land/p/nt/uassert/v0"
	"gno.land/p/nt/urequire/v0"
)

func resetState() {
	auditors = avl.NewTree()
	attestations = avl.NewTree()
	latestByPkg = avl.NewTree()
	digestIndex = avl.NewTree()
	challenges = avl.NewTree()
	nextAttestID = 0
	nextChallengID = 0
}

func TestAttestationLifecycleChallengeAndSanitization(cur realm, t *testing.T) {
	defer resetState()

	auditor := testutils.TestAddress("auditor1")
	researcher := testutils.TestAddress("researcher1")
	srcHash := "1111111111111111111111111111111111111111111111111111111111111111"
	repHash := "2222222222222222222222222222222222222222222222222222222222222222"
	evHash := "3333333333333333333333333333333333333333333333333333333333333333"

	testing.SetRealm(testing.NewUserRealm(auditor))
	RegisterAuditor(cross(cur), "Ironclad | Core", "Automated Gno security auditor", "https://ironclad.example")

	aid := PublishAttestation(
		cross(cur),
		"gno.land/r/demo/tollgate",
		srcHash,
		repHash,
		"ironclad-1.0.0",
		0, 0, 0, 0, 0,
		"",
		"Zero findings across all 14 threat classes.",
		"https://github.com/mevlanayalcin/ironclad",
	)
	uassert.Equal(t, uint64(1), aid)

	att, ok := GetLatestForPackage("gno.land/r/demo/tollgate")
	urequire.True(t, ok)
	uassert.Equal(t, 100, att.Score)
	uassert.Equal(t, "A+", att.Grade)
	uassert.Equal(t, StatusValid, att.Status)

	foundID, ok := VerifyAttestationByDigest(att.Digest)
	urequire.True(t, ok)
	uassert.Equal(t, aid, foundID)

	// Duplicate identical attestation must fail
	uassert.AbortsWithMessage(t, cur, "ironclad: identical attestation already published", func() {
		PublishAttestation(cross(cur), "gno.land/r/demo/tollgate", srcHash, repHash, "ironclad-1.0.0", 0, 0, 0, 0, 0, "", "dup", "")
	})

	// Security researcher challenges attestation
	testing.SetRealm(testing.NewUserRealm(researcher))
	cid := ChallengeAttestation(cross(cur), aid, "GNO-TC3", evHash, "Unchecked Teller interface parameter in helper")
	uassert.Equal(t, uint64(1), cid)

	attCh, _ := GetAttestation(aid)
	uassert.Equal(t, StatusChallenged, attCh.Status)
	uassert.Equal(t, 1, attCh.ChallengeCount)

	// Non-auditor cannot revoke
	uassert.AbortsWithMessage(t, cur, "ironclad: only original auditor may revoke attestation", func() {
		RevokeAttestation(cross(cur), aid, "not mine")
	})

	// Original auditor revokes
	testing.SetRealm(testing.NewUserRealm(auditor))
	RevokeAttestation(cross(cur), aid, "Superseded by patched v2 audit")
	attRev, _ := GetAttestation(aid)
	uassert.Equal(t, StatusRevoked, attRev.Status)

	// Verify Markdown sanitization and JSON routes
	home := Render("")
	uassert.True(t, strings.Contains(home, "Ironclad"))
	audPage := Render("auditors")
	uassert.True(t, strings.Contains(audPage, `\|`))
	js := Render("json/summary")
	uassert.True(t, strings.Contains(js, `"protocol":"ironclad-v1"`))
}
