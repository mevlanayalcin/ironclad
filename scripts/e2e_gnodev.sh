#!/usr/bin/env bash
set -euo pipefail

GNOROOT="${GNOROOT:-/home/ubuntu/gnome-tavern/gno}"
BIN="${GNO_BIN_DIR:-/home/ubuntu/gnome-tavern/bin}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADDR="${IRONCLAD_ADDR:-$(cat /home/ubuntu/gnome-tavern/keys/address.txt)}"
KEYHOME="/home/ubuntu/gnome-tavern/keys/gnokey_home"
PW="$(cat /home/ubuntu/gnome-tavern/keys/.pw)"

RPC_PORT=37657
WEB_PORT=39888
SRV_PORT=38502
RPC_URL="http://127.0.0.1:${RPC_PORT}"
P_PATH="gno.land/p/${ADDR}/ironclad"
R_PATH="gno.land/r/${ADDR}/ironclad"

cleanup() {
  set +e
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
  [ -n "${GNODEV_PID:-}" ] && kill "$GNODEV_PID" 2>/dev/null || true
}
trap cleanup EXIT

wait_next_block() {
  local h0 h1
  h0=$(curl -sS "${RPC_URL}/status" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result']['sync_info']['latest_block_height']))")
  for _ in $(seq 1 20); do
    sleep 0.35
    h1=$(curl -sS "${RPC_URL}/status" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result']['sync_info']['latest_block_height']))")
    if [ "$h1" -gt "$h0" ]; then return 0; fi
  done
}

echo "[1/5] Starting isolated gnodev v1.8.0-rc.1 on ${RPC_URL}..."
GNOROOT="$GNOROOT" "$BIN/gnodev" local \
  -C /tmp \
  -root "$GNOROOT" \
  -paths "gno.land/p/nt/avl/v0,gno.land/p/nt/ufmt/v0,gno.land/p/nt/seqid/v0,gno.land/p/nt/markdown/sanitize/v0,gno.land/p/nt/uassert/v0,gno.land/p/nt/urequire/v0,gno.land/p/nt/testutils/v0" \
  -node-rpc-listener "127.0.0.1:${RPC_PORT}" \
  -web-listener "127.0.0.1:${WEB_PORT}" \
  -add-account "${ADDR}=1000000000ugnot" \
  -no-watch -no-replay -empty-blocks \
  > /tmp/ironclad-gnodev.log 2>&1 &
GNODEV_PID=$!

for _ in $(seq 1 90); do
  if curl -sS "${RPC_URL}/status" 2>/dev/null | grep -q '"latest_block_height"'; then break; fi
  sleep 0.5
done
CHAIN_ID=$(curl -sS "${RPC_URL}/status" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['node_info']['network'])")
echo "    gnodev ready: chain_id=${CHAIN_ID}"

echo "[2/5] Deploying /p/ironclad then /r/ironclad..."
printf "%s\n" "$PW" | "$BIN/gnokey" maketx addpkg deployer \
  -home "$KEYHOME" -insecure-password-stdin \
  -remote "$RPC_URL" -chainid "$CHAIN_ID" -broadcast \
  -gas-fee 1000000ugnot -gas-wanted 40000000 -max-deposit 50000000ugnot \
  -pkgpath "$P_PATH" -pkgdir "$ROOT/gno/p/${ADDR}/ironclad"
wait_next_block

printf "%s\n" "$PW" | "$BIN/gnokey" maketx addpkg deployer \
  -home "$KEYHOME" -insecure-password-stdin \
  -remote "$RPC_URL" -chainid "$CHAIN_ID" -broadcast \
  -gas-fee 1000000ugnot -gas-wanted 80000000 -max-deposit 100000000ugnot \
  -pkgpath "$R_PATH" -pkgdir "$ROOT/gno/r/${ADDR}/ironclad"
wait_next_block

echo "[3/5] Scanning deployed r/ironclad remotely via vm/qfile & publishing on-chain attestation..."
SCAN_JSON=$("$ROOT/bin/ironclad" scan --remote "$RPC_URL" --format json "$R_PATH")
SRC_HASH=$(echo "$SCAN_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['grade']=='A+' and d['score']==100, d; print(d['sourceHash'])")
REP_HASH=$(echo "$SCAN_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['reportDigest'])")
VER=$(echo "$SCAN_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['analyzerVersion'])")

printf "%s\n" "$PW" | "$BIN/gnokey" maketx call deployer \
  -home "$KEYHOME" -insecure-password-stdin \
  -remote "$RPC_URL" -chainid "$CHAIN_ID" -broadcast \
  -gas-fee 1000000ugnot -gas-wanted 20000000 \
  -pkgpath "$R_PATH" -func RegisterAuditor \
  -args "IroncladBot" -args "Automated Gno Threat-Class Analyzer" -args "https://github.com/mevlanayalcin/ironclad"
wait_next_block

printf "%s\n" "$PW" | "$BIN/gnokey" maketx call deployer \
  -home "$KEYHOME" -insecure-password-stdin \
  -remote "$RPC_URL" -chainid "$CHAIN_ID" -broadcast \
  -gas-fee 1000000ugnot -gas-wanted 20000000 \
  -pkgpath "$R_PATH" -func PublishAttestation \
  -args "$R_PATH" -args "$SRC_HASH" -args "$REP_HASH" -args "$VER" \
  -args "0" -args "0" -args "0" -args "0" -args "0" \
  -args "" -args "Zero findings across all 15 Gno security & lint rules." -args "https://github.com/mevlanayalcin/ironclad"
wait_next_block

echo "[4/5] Starting ironclad-server & verifying live remote scan + on-chain attestation join..."
"$ROOT/bin/ironclad-server" --listen "127.0.0.1:${SRV_PORT}" --rpc "$RPC_URL" --realm "$R_PATH" --web "$ROOT/web" > /tmp/ironclad-srv.log 2>&1 &
SRV_PID=$!
for _ in $(seq 1 20); do
  if curl -sS "http://127.0.0.1:${SRV_PORT}/api/health" >/dev/null 2>&1; then break; fi
  sleep 0.25
done

API_OUT=$(curl -sS -X POST "http://127.0.0.1:${SRV_PORT}/api/scan/remote" \
  -H "Content-Type: application/json" \
  -d "{\"rpc\":\"${RPC_URL}\",\"pkgPath\":\"${R_PATH}\",\"chainId\":\"${CHAIN_ID}\"}")
echo "$API_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['report']['grade'] == 'A+', d
att = d['onChainAttestation']
assert att['grade'] == 'A+' and att['score'] == 100, att
assert att['digest'] == d['attestationDigest'], (att['digest'], d['attestationDigest'])
print('VERIFIED LIVE REMOTE SCAN + ON-CHAIN ATTESTATION DIGEST MATCH:', att['digest'])
"

echo "[5/5] Verifying SARIF v2.1.0 output..."
"$ROOT/bin/ironclad" scan --remote "$RPC_URL" --format sarif "$R_PATH" | python3 -c "import sys,json; s=json.load(sys.stdin); assert s['version']=='2.1.0' and len(s['runs'][0]['tool']['driver']['rules'])==15"
echo "=== IRONCLAD E2E GNODEV 100% GREEN ==="
