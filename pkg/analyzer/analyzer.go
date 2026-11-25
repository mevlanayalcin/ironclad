package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	reStandaloneCrossing = regexp.MustCompile(`(?m)^(\s*)crossing\(\)\s*$`)
)

// preprocessGno translates Gno-only syntax edge cases into valid Go syntax while
// preserving 1-to-1 line numbers for exact diagnostic reporting.
func preprocessGno(src string) string {
	return reStandaloneCrossing.ReplaceAllString(src, "${1}_ = gno__crossing()")
}

// AnalyzeDirectory scans all non-test .gno files in a local directory.
func AnalyzeDirectory(dir, targetName string) (Report, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Report{}, err
	}
	files := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".gno") || strings.HasSuffix(name, "_test.gno") || strings.HasSuffix(name, "_filetest.gno") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return Report{}, err
		}
		files[name] = string(raw)
	}
	if targetName == "" {
		targetName = dir
	}
	return AnalyzeSources(targetName, files), nil
}

// AnalyzeSources runs all 15 Ironclad AST rules over a set of Gno source files.
func AnalyzeSources(target string, files map[string]string) Report {
	isRealm := strings.Contains(target, "/r/") || detectRealmPackage(files)
	fset := token.NewFileSet()

	type parsedFile struct {
		name     string
		raw      string
		lines    []string
		astFile  *ast.File
		imports  map[string]string // alias -> path
		hasSanit bool
	}

	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)

	parsed := make([]*parsedFile, 0, len(names))
	packageGuardHelpers := make(map[string]bool)
	packageHasSanitize := false
	packageGlobals := make(map[string]bool)

	for _, name := range names {
		raw := files[name]
		norm := preprocessGno(raw)
		af, err := parser.ParseFile(fset, name, norm, parser.ParseComments)
		if err != nil {
			continue
		}
		pf := &parsedFile{
			name:    name,
			raw:     raw,
			lines:   strings.Split(raw, "\n"),
			astFile: af,
			imports: make(map[string]string),
		}
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			alias := filepath.Base(p)
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			pf.imports[alias] = p
			if strings.Contains(p, "markdown/sanitize") {
				pf.hasSanit = true
				packageHasSanitize = true
			}
		}

		// Pre-pass: discover package-local cur.IsCurrent() helper functions and globals
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok == token.VAR {
					for _, spec := range d.Specs {
						vs := spec.(*ast.ValueSpec)
						for _, ident := range vs.Names {
							packageGlobals[ident.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && d.Body != nil {
					if hasRealmParam(d.Type) && containsCall(d.Body, "IsCurrent") {
						packageGuardHelpers[d.Name.Name] = true
					}
					if hasRealmParam(d.Type) && containsCall(d.Body, "IsUserCall") {
						packageGuardHelpers[d.Name.Name+":usercall"] = true
					}
				}
			}
		}
		parsed = append(parsed, pf)
	}

	// Expand helper transitivity one level (e.g. mustDirectUserPayment -> mustCurrent)
	for _, pf := range parsed {
		for _, decl := range pf.astFile.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || !hasRealmParam(fn.Type) {
				continue
			}
			for helper := range packageGuardHelpers {
				if !strings.Contains(helper, ":") && containsIdentCall(fn.Body, helper) {
					packageGuardHelpers[fn.Name.Name] = true
				}
			}
		}
	}

	var findings []Finding
	emit := func(pf *parsedFile, pos token.Pos, ruleID, detail string) {
		meta := RuleCatalog[ruleID]
		position := fset.Position(pos)
		snip := ""
		if position.Line >= 1 && position.Line <= len(pf.lines) {
			snip = strings.TrimSpace(pf.lines[position.Line-1])
		}
		findings = append(findings, Finding{
			RuleID:      ruleID,
			ThreatClass: meta.ThreatClass,
			Severity:    meta.Severity,
			Title:       meta.Title,
			Message:     detail,
			File:        pf.name,
			Line:        position.Line,
			Column:      position.Column,
			Snippet:     snip,
			Remediation: meta.Remediation,
			Reference:   meta.Reference,
		})
	}

	for _, pf := range parsed {
		hasUnsafeImport := false
		for _, path := range pf.imports {
			if path == "chain/runtime/unsafe" {
				hasUnsafeImport = true
			}
		}

		// 1. Inspect type declarations (GNO-TC1A, GNO-TC3 sealing)
		for _, decl := range pf.astFile.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			if gd.Tok == token.TYPE {
				for _, spec := range gd.Specs {
					ts := spec.(*ast.TypeSpec)
					iface, ok := ts.Type.(*ast.InterfaceType)
					if !ok || iface.Methods == nil {
						continue
					}
					for _, m := range iface.Methods.List {
						ft, ok := m.Type.(*ast.FuncType)
						if !ok {
							continue
						}
						if hasRealmParam(ft) {
							mName := ""
							if len(m.Names) > 0 {
								mName = m.Names[0].Name
							}
							emit(pf, m.Pos(), "GNO-TC1A",
								"interface "+ts.Name.Name+" declares method "+mName+" accepting realm capability token")
						}
						for _, n := range m.Names {
							if isSealingMarkerName(n.Name) && ft.Params.NumFields() == 0 {
								emit(pf, m.Pos(), "GNO-TC3",
									"interface "+ts.Name.Name+" relies on unexported marker method "+n.Name+"() which is bypassable via embedding in Gno")
							}
						}
					}
				}
			}

			// 2. Inspect package-level vars (GNO-SEC04, GLOBAL001)
			if gd.Tok == token.VAR {
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					typeStr := exprString(vs.Type)
					if typeStr == "realm" || strings.HasSuffix(typeStr, ".Banker") {
						emit(pf, vs.Pos(), "GNO-SEC04",
							"package-level variable persists "+typeStr+" capability across transactions")
					}
					for _, val := range vs.Values {
						if containsCall(val, "NewBanker") {
							emit(pf, val.Pos(), "GNO-SEC04",
								"package-level variable stores banker.NewBanker(...) capability permanently")
						}
					}
					if isRealm {
						for idx, ident := range vs.Names {
							if ast.IsExported(ident.Name) {
								// Allow idiomatic sentinel errors (var ErrFoo = errors.New(...))
								if strings.HasPrefix(ident.Name, "Err") && idx < len(vs.Values) && containsCall(vs.Values[idx], "New") {
									continue
								}
								emit(pf, ident.Pos(), "GLOBAL001",
									"exported mutable global var "+ident.Name+" exposes realm state directly")
							}
						}
					}
				}
			}
		}

		// 3. Inspect function declarations
		for _, decl := range pf.astFile.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			fnName := fn.Name.Name
			isExported := fn.Recv == nil && ast.IsExported(fnName)
			realmParamName := getRealmParamName(fn.Type)

			// GNO-SEC01: Crossing function missing cur.IsCurrent()
			if isRealm && isExported && realmParamName != "" && fnName != "init" {
				guarded := containsCall(fn.Body, "IsCurrent")
				if !guarded {
					for helper := range packageGuardHelpers {
						if !strings.Contains(helper, ":") && containsIdentCall(fn.Body, helper) {
							guarded = true
							break
						}
					}
				}
				if !guarded {
					emit(pf, fn.Pos(), "GNO-SEC01",
						"exported crossing function "+fnName+" accepts "+realmParamName+" realm without calling "+realmParamName+".IsCurrent()")
				}
			}

			// GNO-TC2: Designation-forgery parameters on exported mutating/auth functions
			if isRealm && isExported && fnName != "Render" && fnName != "init" && fn.Type.Params != nil && !isReadOnlyGetterName(fnName) {
				for _, field := range fn.Type.Params.List {
					tStr := exprString(field.Type)
					for _, pName := range field.Names {
						low := strings.ToLower(pName.Name)
						if tStr == "address" && (low == "caller" || low == "sender" || low == "origin" || low == "admin") {
							emit(pf, pName.Pos(), "GNO-TC2",
								"exported function "+fnName+" accepts caller-controlled address parameter "+pName.Name+" instead of cur.Previous().Address()")
						}
						if tStr == "string" && (low == "callerpkg" || low == "callerpkgpath") {
							emit(pf, pName.Pos(), "GNO-TC2",
								"exported function "+fnName+" accepts caller-controlled pkgPath parameter "+pName.Name)
						}
					}
				}
			}

			// GNO-TC3: Unchecked open interface parameters (grc20.Teller, banker.Banker, etc.)
			if isRealm && isExported && fn.Type.Params != nil {
				for _, field := range fn.Type.Params.List {
					tStr := exprString(field.Type)
					if isSuspiciousInterfaceType(tStr) {
						hasAllowlist := containsPrefixCall(fn.Body, "IsCanonical") || containsTypeSwitch(fn.Body)
						if !hasAllowlist {
							emit(pf, field.Pos(), "GNO-TC3",
								"exported function "+fnName+" accepts open interface "+tStr+" without IsCanonical* check or concrete type switch")
						}
					}
				}
			}

			// GNO-TC4: Caller-supplied func() callback invoked in exported realm function
			if isRealm && isExported && fn.Type.Params != nil {
				for _, field := range fn.Type.Params.List {
					if _, isFunc := field.Type.(*ast.FuncType); isFunc {
						for _, pName := range field.Names {
							if containsIdentCall(fn.Body, pName.Name) {
								emit(pf, field.Pos(), "GNO-TC4",
									"exported function "+fnName+" invokes caller-supplied callback "+pName.Name+" under realm authority")
							}
						}
					}
				}
			}

			// GNO-SEC03: Exported realm function returning pointer to mutable state / *avl.Tree
			if isRealm && isExported && fn.Type.Results != nil {
				for _, res := range fn.Type.Results.List {
					if star, ok := res.Type.(*ast.StarExpr); ok {
						tStr := exprString(star)
						emit(pf, res.Pos(), "GNO-SEC03",
							"exported function "+fnName+" returns pointer "+tStr+" which may leak realm write authority via borrow rule #2")
					}
				}
			}

			// GNO-SEC02: IsUser() used instead of IsUserCall(), or unguarded OriginSend()
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "IsUser" {
					emit(pf, call.Pos(), "GNO-SEC02",
						"function "+fnName+" checks IsUser() which permits ephemeral MsgRun realms; use cur.Previous().IsUserCall()")
				}
				if sel.Sel.Name == "OriginSend" {
					hasGuard := containsCall(fn.Body, "IsUserCall") || containsCall(fn.Body, "AssertOriginCall")
					if !hasGuard {
						for helper := range packageGuardHelpers {
							if strings.HasSuffix(helper, ":usercall") && containsIdentCall(fn.Body, strings.TrimSuffix(helper, ":usercall")) {
								hasGuard = true
								break
							}
						}
					}
					if !hasGuard {
						emit(pf, call.Pos(), "GNO-SEC02",
							"OriginSend() called in "+fnName+" without cur.Previous().IsUserCall() or runtime.AssertOriginCall() guard")
					}
				}
				// GNO-SEC05: unsafe.PreviousRealm / CurrentRealm / OriginCaller alongside cur realm
				if hasUnsafeImport && realmParamName != "" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "unsafe" {
						if sel.Sel.Name == "PreviousRealm" || sel.Sel.Name == "CurrentRealm" || sel.Sel.Name == "OriginCaller" {
							emit(pf, call.Pos(), "GNO-SEC05",
								"unsafe."+sel.Sel.Name+"() bypasses cur.IsCurrent() safety in crossing function "+fnName)
						}
					}
				}
				// GNO-TC1B: passing raw cur realm into a non-banker/non-cross/non-helper external selector call
				if realmParamName != "" && isExternalCurLeak(call, sel, realmParamName) {
					emit(pf, call.Pos(), "GNO-TC1B",
						"live realm handle "+realmParamName+" passed directly into "+exprString(sel)+"() (prefer passing cur.Previous().Address() or cross(cur))")
				}
				// GNO-SEC07: GetCoins(...).AmountOf(...)
				if sel.Sel.Name == "AmountOf" {
					if inner, ok := sel.X.(*ast.CallExpr); ok {
						if isel, ok := inner.Fun.(*ast.SelectorExpr); ok && isel.Sel.Name == "GetCoins" {
							emit(pf, inner.Pos(), "GNO-SEC07",
								"GetCoins(...).AmountOf(...) scans every denom held by the address; use O(1) GetCoin(addr, denom)")
						}
					}
				}
				// AVL001: unbounded Iterate / ReverseIterate
				if isRealm && (sel.Sel.Name == "Iterate" || sel.Sel.Name == "ReverseIterate") && len(call.Args) == 3 {
					if isEmptyStringLit(call.Args[0]) && isEmptyStringLit(call.Args[1]) && !callbackHasEarlyStop(call.Args[2]) {
						emit(pf, call.Pos(), "AVL001",
							"unbounded "+sel.Sel.Name+"(\"\", \"\", ...) in "+fnName+" risks gas DoS as tree grows; use IterateByOffset / ReverseIterateByOffset")
					}
				}
				return true
			})

			// GNO-SEC07 loop check: GetCoins inside for/range loop
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n.(type) {
				case *ast.ForStmt, *ast.RangeStmt:
					ast.Inspect(n, func(inner ast.Node) bool {
						if c, ok := inner.(*ast.CallExpr); ok {
							if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "GetCoins" {
								emit(pf, c.Pos(), "GNO-SEC07",
									"GetCoins() called inside a loop in "+fnName+" causes quadratic unsolicited-denom gas DoS; use GetCoin()")
							}
						}
						return true
					})
					return false
				}
				return true
			})

			// Render checks: GNO-SEC06 & RENDER001
			if isRealm && fn.Recv == nil && fnName == "Render" {
				if !pf.hasSanit && !packageHasSanitize {
					if renderConcatenatesInput(fn) {
						emit(pf, fn.Pos(), "GNO-SEC06",
							"Render(path) concatenates dynamic strings into Markdown without importing gno.land/p/nt/markdown/sanitize/v0")
					}
				}
				// RENDER001: mutation of package globals or avl.Tree Set/Remove inside Render
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					switch stmt := n.(type) {
					case *ast.AssignStmt:
						if stmt.Tok != token.DEFINE {
							for _, lhs := range stmt.Lhs {
								if id, ok := lhs.(*ast.Ident); ok && packageGlobals[id.Name] {
									emit(pf, stmt.Pos(), "RENDER001",
										"Render mutates package-level global "+id.Name)
								}
							}
						}
					case *ast.IncDecStmt:
						if id, ok := stmt.X.(*ast.Ident); ok && packageGlobals[id.Name] {
							emit(pf, stmt.Pos(), "RENDER001",
								"Render mutates package-level global "+id.Name)
						}
					case *ast.CallExpr:
						if sel, ok := stmt.Fun.(*ast.SelectorExpr); ok {
							if sel.Sel.Name == "Set" || sel.Sel.Name == "Remove" || sel.Sel.Name == "SendCoins" {
								emit(pf, stmt.Pos(), "RENDER001",
									"Render invokes mutating method ."+sel.Sel.Name+"()")
							}
						}
					}
					return true
				})
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].RuleID < findings[j].RuleID
	})

	var counts Counts
	ruleSet := make(map[string]struct{})
	for _, f := range findings {
		ruleSet[f.RuleID] = struct{}{}
		switch f.Severity {
		case SeverityCritical:
			counts.Critical++
		case SeverityHigh:
			counts.High++
		case SeverityMedium:
			counts.Medium++
		case SeverityLow:
			counts.Low++
		default:
			counts.Info++
		}
	}
	rules := make([]string, 0, len(ruleSet))
	for r := range ruleSet {
		rules = append(rules, r)
	}
	sort.Strings(rules)

	score := ComputeScore(counts)
	return Report{
		Target:          target,
		AnalyzerVersion: AnalyzerVersion,
		FilesScanned:    len(parsed),
		SourceHash:      HashSources(files),
		ReportDigest:    HashFindings(findings),
		Counts:          counts,
		Score:           score,
		Grade:           ComputeGrade(score, counts),
		RulesTriggered:  rules,
		Findings:        findings,
	}
}

func detectRealmPackage(files map[string]string) bool {
	for _, src := range files {
		if strings.Contains(src, "cur realm") || strings.Contains(src, "func Render(") || strings.Contains(src, "chain/banker") {
			return true
		}
	}
	return false
}

func hasRealmParam(ft *ast.FuncType) bool {
	return getRealmParamName(ft) != ""
}

func getRealmParamName(ft *ast.FuncType) string {
	if ft == nil || ft.Params == nil {
		return ""
	}
	for _, f := range ft.Params.List {
		if exprString(f.Type) == "realm" {
			if len(f.Names) > 0 {
				return f.Names[0].Name
			}
			return "realm"
		}
	}
	return ""
}

func isSealingMarkerName(name string) bool {
	if ast.IsExported(name) {
		return false
	}
	low := strings.ToLower(name)
	return strings.Contains(low, "seal") || strings.Contains(low, "canonical") || strings.HasPrefix(low, "is")
}

func isReadOnlyGetterName(name string) bool {
	for _, p := range []string{"Get", "Has", "Check", "Verify", "Is", "Total", "Balance", "Allowance", "List", "Count", "Query"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func isSuspiciousInterfaceType(t string) bool {
	for _, known := range []string{"Teller", "Banker", "Authority", "Authenticator", "Approver", "Signer", "Handler", "Verifier"} {
		if strings.HasSuffix(t, "."+known) || t == known {
			return true
		}
	}
	return false
}

func isExternalCurLeak(call *ast.CallExpr, sel *ast.SelectorExpr, curName string) bool {
	// Allowed: banker.NewBanker(..., cur), cross(cur), or cur.<method>()
	if id, ok := sel.X.(*ast.Ident); ok {
		if id.Name == curName || id.Name == "banker" || id.Name == "grc20" {
			return false
		}
	}
	for _, arg := range call.Args {
		if id, ok := arg.(*ast.Ident); ok && id.Name == curName {
			return true
		}
	}
	return false
}

func isEmptyStringLit(e ast.Expr) bool {
	bl, ok := e.(*ast.BasicLit)
	return ok && bl.Kind == token.STRING && (bl.Value == `""` || bl.Value == "``")
}

func callbackHasEarlyStop(e ast.Expr) bool {
	fn, ok := e.(*ast.FuncLit)
	if !ok || fn.Body == nil {
		return false
	}
	hasTrue := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if ret, ok := n.(*ast.ReturnStmt); ok {
			for _, r := range ret.Results {
				if id, ok := r.(*ast.Ident); ok && id.Name == "true" {
					hasTrue = true
				}
			}
		}
		return true
	})
	return hasTrue
}

func renderConcatenatesInput(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if bin, ok := n.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
			found = true
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Sprintf" || sel.Sel.Name == "WriteString") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func containsCall(root ast.Node, methodName string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == methodName {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func containsPrefixCall(root ast.Node, prefix string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			switch f := c.Fun.(type) {
			case *ast.SelectorExpr:
				if strings.HasPrefix(f.Sel.Name, prefix) {
					found = true
					return false
				}
			case *ast.Ident:
				if strings.HasPrefix(f.Name, prefix) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func containsIdentCall(root ast.Node, fnName string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == fnName {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func containsTypeSwitch(root ast.Node) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if _, ok := n.(*ast.TypeSwitchStmt); ok {
			found = true
			return false
		}
		if _, ok := n.(*ast.TypeAssertExpr); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case nil:
		return ""
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.ArrayType:
		return "[]" + exprString(t.Elt)
	case *ast.FuncType:
		return "func"
	default:
		return ""
	}
}
