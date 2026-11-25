package analyzer

import (
	"testing"
)

func TestCrossLanguageAttestationDigestMatchesGno(t *testing.T) {
	got := AttestationDigest(
		"onyx-1",
		"gno.land/r/demo/vault",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"ironclad-1.0.0",
		Counts{Medium: 1, Low: 2},
	)
	const wantFromGno = "e082817fb6ae2a2875880ef8b105657b6ca6d910763971e00db093e4940ce563"
	if got != wantFromGno {
		t.Fatalf("digest mismatch: Go=%s Gno=%s", got, wantFromGno)
	}
}

func TestAllVulnerableRulesDetected(t *testing.T) {
	vulnSrc := `package vuln

import (
	"chain/banker"
	"chain/runtime/unsafe"
	"gno.land/p/nt/avl/v0"
	"gno.land/p/nt/grc20/v0"
)

type BadHooks interface {
	OnAction(cur realm, amt int64)
	isCanonical()
}

var (
	ExportedTree = avl.NewTree()
	savedRealm   realm
	savedBanker  = banker.NewBanker(banker.BankerTypeRealmSend, nil)
	counter      int
)

func AdminMint(cur realm, caller address, teller grc20.Teller, cb func()) *avl.Tree {
	_ = unsafe.PreviousRealm()
	if !cur.Previous().IsUser() {
		panic("not user")
	}
	_ = unsafe.OriginSend()
	teller.Transfer(caller, 10)
	cb()
	external.Notify(cur)
	_ = banker.NewReadonlyBanker().GetCoins(caller).AmountOf("ugnot")
	ExportedTree.Iterate("", "", func(k string, v any) bool {
		return false
	})
	return ExportedTree
}

func Render(path string) string {
	counter++
	ExportedTree.Set("last", path)
	return "# Vault: " + path
}
`
	rep := AnalyzeSources("gno.land/r/test/vuln", map[string]string{"vuln.gno": vulnSrc})
	triggered := make(map[string]bool)
	for _, f := range rep.Findings {
		triggered[f.RuleID] = true
	}
	expectedRules := []string{
		"GNO-TC1A", "GNO-TC1B", "GNO-TC2", "GNO-TC3", "GNO-TC4",
		"GNO-SEC01", "GNO-SEC02", "GNO-SEC03", "GNO-SEC04", "GNO-SEC05",
		"GNO-SEC06", "GNO-SEC07", "AVL001", "GLOBAL001", "RENDER001",
	}
	for _, r := range expectedRules {
		if !triggered[r] {
			t.Errorf("expected rule %s to fire on vulnerable fixture; triggered=%v", r, rep.RulesTriggered)
		}
	}
	if rep.Grade != "F" {
		t.Fatalf("expected F grade on vulnerable fixture, got %s (score=%d)", rep.Grade, rep.Score)
	}

	sarifBytes, err := ToSARIF(rep)
	if err != nil || len(sarifBytes) < 100 {
		t.Fatalf("SARIF export failed: %v", err)
	}
}

func TestCleanRealmScoresAPlus(t *testing.T) {
	cleanSrc := `package clean

import (
	"chain/banker"
	"chain/runtime/unsafe"
	"gno.land/p/nt/avl/v0"
	"gno.land/p/nt/markdown/sanitize/v0"
)

var store = avl.NewTree()

func Deposit(cur realm) {
	if !cur.IsCurrent() {
		panic("spoofed")
	}
	if !cur.Previous().IsUserCall() {
		panic("user call only")
	}
	amt := unsafe.OriginSend().AmountOf("ugnot")
	if amt <= 0 {
		panic("zero")
	}
	_ = banker.NewReadonlyBanker().GetCoin(cur.Address(), "ugnot")
	store.Set(cur.Previous().Address().String(), amt)
}

func Render(path string) string {
	return "# Clean: " + sanitize.InlineText(path)
}
`
	rep := AnalyzeSources("gno.land/r/test/clean", map[string]string{"clean.gno": cleanSrc})
	if len(rep.Findings) != 0 || rep.Score != 100 || rep.Grade != "A+" {
		t.Fatalf("expected clean realm A+ (100), got %s (%d): %+v", rep.Grade, rep.Score, rep.Findings)
	}
}
