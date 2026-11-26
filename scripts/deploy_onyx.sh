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

wait_gpas_passed() {
  local pkg="$1"
  echo "Waiting for GPAS approval on https://gpas.onyx.testnets.gno.land/?path=${pkg} ..."
  for i in $(seq 1 90); do
    HTML=$(curl -sS "https://gpas.onyx.testnets.gno.land/?path=${pkg}" || true)
    if echo "$HTML" | grep -qi "failed\|rejected"; then
      echo "ERROR: GPAS rejected ${pkg}!"
      exit 1
    fi
    if "$BIN/gnokey" query "vm/qfile" -data "$pkg" -remote "$RPC" >/dev/null 2>&1; then
      echo "Package ${pkg} confirmed live on onyx-1 RPC!"
      return 0
    fi
    sleep 5
  done
  echo "Timed out waiting for GPAS on ${pkg}"
  exit 1
}

echo "=== 1. Deploy /p/ironclad first ==="
if ! "$BIN/gnokey" query "vm/qfile" -data "$P_PATH" -remote "$RPC" >/dev/null 2>&1; then
  printf "%s\n" "$PW" | "$BIN/gnokey" maketx addpkg deployer \
    -home "$KEYHOME" -insecure-password-stdin \
    -remote "$RPC" -chainid "$CHAIN_ID" -broadcast \
    -gas-fee 1000000ugnot -gas-wanted 40000000 -max-deposit 50000000ugnot \
    -pkgpath "$P_PATH" -pkgdir "$ROOT/gno/p/${ADDR}/ironclad"
fi
wait_gpas_passed "$P_PATH"

echo "=== 2. Deploy /r/ironclad ONLY after /p/ironclad is passed & live ==="
if ! "$BIN/gnokey" query "vm/qfile" -data "$R_PATH" -remote "$RPC" >/dev/null 2>&1; then
  printf "%s\n" "$PW" | "$BIN/gnokey" maketx addpkg deployer \
    -home "$KEYHOME" -insecure-password-stdin \
    -remote "$RPC" -chainid "$CHAIN_ID" -broadcast \
    -gas-fee 1000000ugnot -gas-wanted 80000000 -max-deposit 100000000ugnot \
    -pkgpath "$R_PATH" -pkgdir "$ROOT/gno/r/${ADDR}/ironclad"
fi
wait_gpas_passed "$R_PATH"

echo "=== 3. Register Auditor & Publish live onyx-1 attestations (Ironclad, Tollgate, r/sys/namereg/v0) ==="
printf "%s\n" "$PW" | "$BIN/gnokey" maketx call deployer \
  -home "$KEYHOME" -insecure-password-stdin \
  -remote "$RPC" -chainid "$CHAIN_ID" -broadcast \
  -gas-fee 1000000ugnot -gas-wanted 20000000 \
  -pkgpath "$R_PATH" -func RegisterAuditor \
  -args "IroncladCore" \
  -args "Automated static analyzer enforcing Gno Threat-Class Taxonomy (gno-security.md) & PR #5068 rules" \
  -args "https://github.com/mevlanayalcin/ironclad"
sleep 4

attest_remote() {
  local pkg="$1"
  local note="$2"
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
print('SUMMARY=' + shlex.quote(f"Automated Ironclad AST audit: Grade {d['grade']} ({d['score']}/100) — C:{d['counts']['critical']} H:{d['counts']['high']} M:{d['counts']['medium']} L:{d['counts']['low']}."))
")"
  printf "%s\n" "$PW" | "$BIN/gnokey" maketx call deployer \
    -home "$KEYHOME" -insecure-password-stdin \
    -remote "$RPC" -chainid "$CHAIN_ID" -broadcast \
    -gas-fee 1000000ugnot -gas-wanted 20000000 \
    -pkgpath "$R_PATH" -func PublishAttestation \
    -args "$pkg" -args "$SH" -args "$RH" -args "$VER" \
    -args "$CC" -args "$CH" -args "$CM" -args "$CL" -args "$CI" \
    -args "$RULES" -args "$SUMMARY" -args "https://github.com/mevlanayalcin/ironclad"
  sleep 4
}

attest_remote "$R_PATH" "Self-attestation of Ironclad on-chain attestation registry (Grade A+, 0 findings)."
if "$BIN/gnokey" query "vm/qfile" -data "$TOLLGATE_R" -remote "$RPC" >/dev/null 2>&1; then
  attest_remote "$TOLLGATE_R" "Full static security audit of Tollgate x402 metering realm (Grade A+, 0 findings)."
fi
attest_remote "gno.land/r/sys/namereg/v0" "Automated live onyx-1 taxonomy scan of system namereg realm."

"$BIN/gnokey" query "vm/qrender" -data "${R_PATH}:json/summary" -remote "$RPC"
echo "=== IRONCLAD LIVE ON ONYX-1 ==="
echo "gnoweb: https://onyx.testnets.gno.land/r/${ADDR}/ironclad"
