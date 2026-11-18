#!/usr/bin/env bash
# Painel do ALVO (terminal 2).
# Modo padrao nesta maquina: JDK 17.0.21 sob Intel SDE (AVX-512 VBMI emulado).
# Sem SDE instalado, cai para Docker (exige AVX-512 nativo no host).
#
# Autor do harness: eduxcode (github.com/eduxcode)
# Primitiva: CVE-2026-114938 - Quang Luong / Calif.io
set -uo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB"
source "$LAB/demo/env.sh"

PORT="8080"
BASE="http://127.0.0.1:${PORT}"
NAME="j4s-demo"
IMG="j4s-demo:lab"
EVID="$LAB/demo/evidence/$(date +%H%M%S)"
mkdir -p "$EVID"

printf '\033[1;35m'
cat <<'EOF'
+--------------------------------------------------------------+
|  ALVO  -  OpenJDK 17.0.21 / POST /decode-exact               |
|  harness: eduxcode (github.com/eduxcode)                     |
|  primitiva: CVE-2026-114938                                  |
+--------------------------------------------------------------+
EOF
printf '\033[0m\n'

if [ "$SDE_MODE" = 1 ]; then
  echo "modo: Intel SDE (AVX-512 VBMI emulado) - sem AWS, 100% local"
  echo "jdk : $("$J4S_JAVA" -version 2>&1 | head -1)"
  "$J4S_JAVAC" -d "$J4S_BUILD" "$LAB/target/DecodeServer.java" || { echo "build falhou"; exit 1; }
  "$SDE" -icx -- "$J4S_JAVA" "${J4S_FLAGS[@]}" \
      -XX:ErrorFile="$EVID/hs_err_%p.log" \
      -Dwarmup=5000 -Dport="$PORT" \
      -cp "$J4S_BUILD" DecodeServer > "$EVID/target.log" 2>&1 &
  TARGET_PID=$!
  trap 'kill "$TARGET_PID" 2>/dev/null' EXIT
else
  echo "modo: Docker (host precisa de AVX-512 VBMI nativo)"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker build -q -t "$IMG" ./target >/dev/null || { echo "build falhou"; exit 1; }
  docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" \
    -e JAVA_OPTS="-XX:ErrorFile=/app/hs_err_%p.log" "$IMG" >/dev/null
  trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT
fi

echo "aguardando o alvo subir (warmup curto + emulacao)..."
for _ in $(seq 1 120); do
  curl -sf -m 2 "$BASE/health" >/dev/null 2>&1 && break
  sleep 1
done

if ! curl -sf -m 2 "$BASE/health" >/dev/null 2>&1; then
  echo "alvo nao subiu"
  [ "$SDE_MODE" = 1 ] && tail -20 "$EVID/target.log"
  [ "$SDE_MODE" = 0 ] && docker logs --tail 20 "$NAME" 2>&1
  exit 1
fi

echo "NO AR: $(curl -s "$BASE/health")"
echo
echo "monitorando /health a cada 2s."
echo

START=$(date +%s)
while :; do
  if [ "$SDE_MODE" = 1 ]; then
    if ! kill -0 "$TARGET_PID" 2>/dev/null; then STATE="crashed"; else STATE="running"; fi
  else
    STATE=$(docker inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null || echo missing)
  fi

  if [ "$STATE" != "running" ]; then
    echo
    echo ">>> ALVO CAIU (status=$STATE) apos $(( $(date +%s) - START ))s"
    echo ">>> ultimas linhas:"
    if [ "$SDE_MODE" = 1 ]; then
      wait "$TARGET_PID" 2>/dev/null
      tail -25 "$EVID/target.log" 2>&1
    else
      docker logs --tail 25 "$NAME" 2>&1
      mkdir -p "$EVID/app"
      docker cp "$NAME:/app/." "$EVID/app/" >/dev/null 2>&1
      [ -f "$EVID/app/hs_err_"*.log ] && cp "$EVID/app/hs_err_"*.log "$EVID/" 2>/dev/null
    fi
    HS=$(ls "$EVID"/hs_err_*.log 2>/dev/null | head -1)
    if [ -n "${HS:-}" ]; then
      echo
      echo ">>> hs_err capturado: $HS"
      grep -E '^#  SIG|^# JRE version|^# Problematic|^# V  \[' "$HS" | head -6
    fi
    echo
    echo ">>> evidencia salva em $EVID"
    break
  fi

  BODY="$(curl -s -m 2 "$BASE/health" 2>/dev/null || true)"
  [ -n "$BODY" ] && printf '[%s] %s\n' "$(date +%H:%M:%S)" "$BODY"
  sleep 2
done
