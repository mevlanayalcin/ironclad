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

func preprocessGno(src string) string {
	return reStandaloneCrossing.ReplaceAllString(src, "${1}_ = gno__crossing()")
}

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

func AnalyzeSources(target string, files map[string]string) Report {
	isRealm := strings.Contains(target, "/r/") || detectRealmPackage(files)
	fset := token.NewFileSet()

	type parsedFile struct {
		name     string
		raw      string
		lines    []string
		astFile  *ast.File
		imports  map[string]string // alias -> path
		sanAlias string            // alias of markdown/sanitize import, if any
	}

	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)

	var findings []Finding
	parsed := make([]*parsedFile, 0, len(names))
	packageGuardHelpers := make(map[string]bool)
	packageGlobals := make(map[string]bool)
	localTypes := make(map[string]bool)
	localInterfaces := make(map[string]bool)
	funcDecls := make(map[string]*ast.FuncDecl)

	for _, name := range names {
		raw := files[name]
		norm := preprocessGno(raw)
		af, err := parser.ParseFile(fset, name, norm, parser.ParseComments)
		if err != nil {
			// A6: Never silently skip unparsable files!
			meta := RuleCatalog["PARSE-ERR"]
			findings = append(findings, Finding{
				RuleID:      "PARSE-ERR",
				ThreatClass: meta.ThreatClass,
				Severity:    meta.Severity,
				Title:       meta.Title,
				Message:     "failed to parse Gno source file: " + err.Error(),
				File:        name,
				Line:        1,
				Column:      1,
				Remediation: meta.Remediation,
				Reference:   meta.Reference,
			})
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
			if len(alias) >= 2 && alias[0] == 'v' && alias[1] >= '0' && alias[1] <= '9' {
				alias = filepath.Base(filepath.Dir(p))
			}
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			pf.imports[alias] = p
			if strings.Contains(p, "markdown/sanitize") {
				pf.sanAlias = alias
			}
		}

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
				if d.Tok == token.TYPE {
					for _, spec := range d.Specs {
						ts := spec.(*ast.TypeSpec)
						localTypes[ts.Name.Name] = true
						if _, ok := ts.Type.(*ast.InterfaceType); ok {
							localInterfaces[ts.Name.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && d.Body != nil {
					funcDecls[d.Name.Name] = d
					if hasRealmParam(d.Type) && (containsCall(d.Body, "IsCurrent") || containsCall(d.Body, "AssertOriginCall")) {
						packageGuardHelpers[d.Name.Name] = true
					}
					if hasRealmParam(d.Type) && (containsCall(d.Body, "IsUserCall") || containsCall(d.Body, "AssertOriginCall")) {
						packageGuardHelpers[d.Name.Name+":usercall"] = true
					}
				}
			}
		}
		parsed = append(parsed, pf)
	}

	// Expand helper transitivity one level
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

	emit := func(pf *parsedFile, pos token.Pos, ruleID, detail string, sevOverride ...Severity) {
		meta := RuleCatalog[ruleID]
		sev := meta.Severity
		if len(sevOverride) > 0 && sevOverride[0] != "" {
			sev = sevOverride[0]
		}
		position := fset.Position(pos)
		snip := ""
		if position.Line >= 1 && position.Line <= len(pf.lines) {
			snip = strings.TrimSpace(pf.lines[position.Line-1])
		}
		// Support explicit //ironclad:ignore RULE-ID inline suppression
		if position.Line >= 1 && position.Line <= len(pf.lines) {
			if strings.Contains(pf.lines[position.Line-1], "ironclad:ignore "+ruleID) {
				return
			}
		}
		findings = append(findings, Finding{
			RuleID:      ruleID,
			ThreatClass: meta.ThreatClass,
			Severity:    sev,
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
						// A7: Only flag actual sealing-marker names, not arbitrary helper predicates.
						for _, n := range m.Names {
							if isSealingMarkerName(n.Name) && ft.Params.NumFields() == 0 && ft.Results.NumFields() == 0 {
								emit(pf, m.Pos(), "GNO-TC3",
									"interface "+ts.Name.Name+" relies on unexported sealing marker "+n.Name+"() which is bypassable via embedding in Gno")
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

			// Track param types for this function (used by GNO-TC1B & GNO-TC4)
			paramIsCallback := make(map[string]bool)
			paramIsInterface := make(map[string]bool)
			if fn.Type.Params != nil {
				for _, field := range fn.Type.Params.List {
					tStr := exprString(field.Type)
					_, isFunc := field.Type.(*ast.FuncType)
					isIface := isSuspiciousInterfaceType(tStr) || localInterfaces[tStr]
					for _, pName := range field.Names {
						if isFunc {
							paramIsCallback[pName.Name] = true
						}
						if isIface {
							paramIsInterface[pName.Name] = true
						}
					}
				}
			}

			// A2: Calibrated GNO-SEC01:
			// Skip `_ realm`, `init`, and `Render`.
			// Fire CRITICAL only when the function actually reads cur.Previous() or cur.Address()
			// without cur.IsCurrent(), runtime.AssertOriginCall(), or a package guard helper.
			if isRealm && isExported && realmParamName != "" && realmParamName != "_" && fnName != "init" && fnName != "Render" {
				readsIdentity := callsMethodOn(fn.Body, realmParamName, "Previous") || callsMethodOn(fn.Body, realmParamName, "Address")
				if readsIdentity {
					guarded := containsCall(fn.Body, "IsCurrent") || containsCall(fn.Body, "AssertOriginCall")
					if !guarded {
						for helper := range packageGuardHelpers {
							if !strings.Contains(helper, ":") && containsIdentCall(fn.Body, helper) {
								guarded = true
								break
							}
						}
					}
					if !guarded {
						// Direct EOA IsUserCall() provides strong frame verification; downgrade to LOW advisory if present.
						if containsCall(fn.Body, "IsUserCall") {
							emit(pf, fn.Pos(), "GNO-SEC01",
								"crossing function "+fnName+" checks IsUserCall() without explicit "+realmParamName+".IsCurrent() check", SeverityLow)
						} else {
							emit(pf, fn.Pos(), "GNO-SEC01",
								"exported crossing function "+fnName+" reads "+realmParamName+".Previous()/Address() without "+realmParamName+".IsCurrent() or AssertOriginCall()")
						}
					}
				}
			}

			// A7: GNO-TC2 designation-forgery check (fixed getter exemptions so IssueTokens is NOT skipped)
			if isRealm && isExported && fnName != "Render" && fnName != "init" && fn.Type.Params != nil && !isReadOnlyGetterName(fnName) {
				for _, field := range fn.Type.Params.List {
					tStr := exprString(field.Type)
					for _, pName := range field.Names {
						low := strings.ToLower(pName.Name)
						if tStr == "address" && (low == "caller" || low == "sender" || low == "origin" || low == "admin" || low == "owner") {
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

			// GNO-TC3: Unchecked open interface parameters
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

			// A5: GNO-TC4 caller-supplied callbacks — allow realm-owned local typed callbacks func(*MyState)
			if isRealm && isExported && fn.Type.Params != nil {
				for _, field := range fn.Type.Params.List {
					ft, isFunc := field.Type.(*ast.FuncType)
					if !isFunc {
						continue
					}
					if callbackUsesRealmOwnedType(ft, localTypes) {
						continue
					}
					for _, pName := range field.Names {
						if containsIdentCall(fn.Body, pName.Name) {
							emit(pf, field.Pos(), "GNO-TC4",
								"exported function "+fnName+" invokes caller-supplied callback "+pName.Name+" under realm authority")
						}
					}
				}
			}

			// A4: GNO-SEC03 pointer return check — skip New* constructors and safe ReadOnlyTree wrappers
			if isRealm && isExported && fn.Type.Results != nil && !strings.HasPrefix(fnName, "New") {
				for _, res := range fn.Type.Results.List {
					if star, ok := res.Type.(*ast.StarExpr); ok {
						tStr := exprString(star)
						if strings.Contains(tStr, "ReadOnlyTree") || strings.Contains(tStr, "ReadOnly") {
							continue
						}
						emit(pf, res.Pos(), "GNO-SEC03",
							"exported function "+fnName+" returns pointer "+tStr+" which may leak realm write authority via borrow rule #2")
					}
				}
			}

			// Inspect statements & call expressions in body
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}

				// A3: Direct callback invocation passing live cur realm: cb(cur)
				if realmParamName != "" && realmParamName != "_" {
					if id, ok := call.Fun.(*ast.Ident); ok && paramIsCallback[id.Name] && argsContainIdent(call.Args, realmParamName) {
						emit(pf, call.Pos(), "GNO-TC1B",
							"live realm handle "+realmParamName+" passed directly into caller-supplied callback "+id.Name+"()")
					}
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
				if hasUnsafeImport && realmParamName != "" && realmParamName != "_" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "unsafe" {
						if sel.Sel.Name == "PreviousRealm" || sel.Sel.Name == "CurrentRealm" || sel.Sel.Name == "OriginCaller" {
							emit(pf, call.Pos(), "GNO-SEC05",
								"unsafe."+sel.Sel.Name+"() bypasses cur.IsCurrent() safety in crossing function "+fnName)
						}
					}
				}
				// A3: Selector call passing raw cur into an interface-typed parameter (never flagging canonical stdlib/dao/grc20 calls)
				if realmParamName != "" && realmParamName != "_" && argsContainIdent(call.Args, realmParamName) {
					if id, ok := sel.X.(*ast.Ident); ok && paramIsInterface[id.Name] {
						emit(pf, call.Pos(), "GNO-TC1B",
							"live realm handle "+realmParamName+" passed directly into interface method "+id.Name+"."+sel.Sel.Name+"()")
					}
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

			// GNO-SEC07 loop check
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

			// Render checks: A7 (verify actual sanitize usage in Render or its callees) + RENDER001
			if isRealm && fn.Recv == nil && fnName == "Render" {
				if renderConcatenatesDynamicInput(fn) && !renderUsesSanitize(fn, pf.sanAlias, funcDecls) {
					emit(pf, fn.Pos(), "GNO-SEC06",
						"Render(path) concatenates dynamic strings into Markdown without calling markdown/sanitize helpers")
				}
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
	return low == "iscanonical" || low == "sealed" || low == "issealed" || low == "seal" ||
		strings.HasPrefix(low, "iscanonical") || strings.HasPrefix(low, "sealed")
}

func isReadOnlyGetterName(name string) bool {
	for _, p := range []string{"Get", "Has", "Check", "Verify", "Total", "Balance", "Allowance", "List", "Count", "Query", "IsValid", "IsActive", "IsPaused", "IsOwner", "IsCanonical"} {
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

func callbackUsesRealmOwnedType(ft *ast.FuncType, localTypes map[string]bool) bool {
	if ft == nil || ft.Params == nil || len(ft.Params.List) == 0 {
		return false
	}
	for _, f := range ft.Params.List {
		tStr := strings.TrimLeft(exprString(f.Type), "*[]")
		if localTypes[tStr] {
			return true
		}
	}
	return false
}

func callsMethodOn(root ast.Node, objName, method string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == method {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == objName {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func argsContainIdent(args []ast.Expr, name string) bool {
	for _, a := range args {
		if id, ok := a.(*ast.Ident); ok && id.Name == name {
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

func renderConcatenatesDynamicInput(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if bin, ok := n.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
			// Flag only if at least one operand is not a literal string
			_, lLit := bin.X.(*ast.BasicLit)
			_, rLit := bin.Y.(*ast.BasicLit)
			if !lLit || !rLit {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func renderUsesSanitize(fn *ast.FuncDecl, sanAlias string, decls map[string]*ast.FuncDecl) bool {
	if sanAlias == "" {
		return false
	}
	visited := make(map[string]bool)
	var check func(body *ast.BlockStmt, depth int) bool
	check = func(body *ast.BlockStmt, depth int) bool {
		if body == nil || depth > 2 {
			return false
		}
		used := false
		ast.Inspect(body, func(n ast.Node) bool {
			if used {
				return false
			}
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := c.Fun.(type) {
			case *ast.SelectorExpr:
				if id, ok := f.X.(*ast.Ident); ok && id.Name == sanAlias {
					used = true
					return false
				}
			case *ast.Ident:
				if !visited[f.Name] {
					if targetFn, exists := decls[f.Name]; exists {
						visited[f.Name] = true
						if check(targetFn.Body, depth+1) {
							used = true
							return false
						}
					}
				}
			}
			return true
		})
		return used
	}
	return check(fn.Body, 0)
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
