#!/usr/bin/env bash
set -euo pipefail

BIN="${GNO_BIN_DIR:-/home/ubuntu/gnome-tavern/bin}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADDR="${IRONCLAD_ADDR:-$(cat /home/ubuntu/gnome-tavern/keys/address.txt)}"
KEYHOME="/home/ubuntu/gnome-tavern/keys/gnokey_home"
PW="$(cat /home/ubuntu/gnome-tavern/keys/.pw)"
RPC="https://rpc.onyx.testnets.gno.land:443"
CHAIN_ID="onyx-1"
P_PATH="gno.land/p/${ADDR}/ironclad"
R_PATH="gno.land/r/${ADDR}/ironclad"
TOLLGATE_R="gno.land/r/${ADDR}/tollgate"

echo "=== 1. Verify /r/ironclad is live on onyx-1 RPC ==="
"$BIN/gnokey" query "vm/qfile" -data "$R_PATH" -remote "$RPC"

echo "=== 2. Register Auditor (IroncladCore) ==="
printf "%s\n" "$PW" | "$BIN/gnokey" maketx call deployer \
  -home "$KEYHOME" -insecure-password-stdin \
  -remote "$RPC" -chainid "$CHAIN_ID" -broadcast \
  -gas-fee 1000000ugnot -gas-wanted 20000000 \
  -pkgpath "$R_PATH" -func RegisterAuditor \
  -args "IroncladCore" \
  -args "Automated Gno AST security analyzer enforcing Nov 2026 gno-security.md Threat Classes & PR #5068 rules" \
  -args "https://github.com/mevlanayalcin/ironclad"
sleep 5

attest_remote() {
  local pkg="$1"
  echo "--- Scanning & Attesting ${pkg} ---"
  local j
  j=$("$ROOT/bin/ironclad" scan --remote "$RPC" --format json "$pkg")
  eval "$(echo "$j" | python3 -c "
import sys, json, shlex
d = json.load(sys.stdin)
print('SH=' + shlex.quote(d['sourceHash']))
print('RH=' + shlex.quote(d['reportDigest']))
print('VER=' + shlex.quote(d['analyzerVersion']))
print('CC=' + str(d['counts']['critical']))
print('CH=' + str(d['counts']['high']))
print('CM=' + str(d['counts']['medium']))
print('CL=' + str(d['counts']['low']))
print('CI=' + str(d['counts']['info']))
print('RULES=' + shlex.quote(','.join(d.get('rulesTriggered') or [])))
print('SUMMARY=' + shlex.quote(f\"Automated Ironclad AST audit on onyx-1: Grade {d['grade']} ({d['score']}/100) — C:{d['counts']['critical']} H:{d['counts']['high']} M:{d['counts']['medium']} L:{d['counts']['low']}.\"))
")"
  printf "%s\n" "$PW" | "$BIN/gnokey" maketx call deployer \
    -home "$KEYHOME" -insecure-password-stdin \
    -remote "$RPC" -chainid "$CHAIN_ID" -broadcast \
    -gas-fee 1000000ugnot -gas-wanted 20000000 \
    -pkgpath "$R_PATH" -func PublishAttestation \
    -args "$pkg" -args "$SH" -args "$RH" -args "$VER" \
    -args "$CC" -args "$CH" -args "$CM" -args "$CL" -args "$CI" \
    -args "$RULES" -args "$SUMMARY" -args "https://github.com/mevlanayalcin/ironclad"
  sleep 5
}

attest_remote "$R_PATH"
if "$BIN/gnokey" query "vm/qfile" -data "$TOLLGATE_R" -remote "$RPC" >/dev/null 2>&1; then
  attest_remote "$TOLLGATE_R"
fi
attest_remote "gno.land/r/sys/namereg/v0"
attest_remote "gno.land/r/gnoland/wugnot"
attest_remote "gno.land/r/gnoland/blog"
attest_remote "gno.land/r/sys/users"

echo "=== 3. Query live on-chain summary ==="
"$BIN/gnokey" query "vm/qrender" -data "${R_PATH}:json/summary" -remote "$RPC"
echo "=== IRONCLAD SEEDED & LIVE ON ONYX-1 ==="
echo "gnoweb: https://onyx.testnets.gno.land/r/${ADDR}/ironclad"
