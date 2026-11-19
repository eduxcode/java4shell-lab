#!/usr/bin/env bash
# TARGET pane (terminal 1).
# Default mode: JDK 17.0.21 under Intel SDE (emulated AVX-512 VBMI).
# Without SDE installed, falls back to Docker (requires native AVX-512 on the host).
#
# Lab author: eduxcode (github.com/eduxcode)
# Primitive: CVE-2026-114938 - Quang Luong / Calif.io
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
|  TARGET  -  OpenJDK 17.0.21 / POST /decode-exact             |
|  lab: eduxcode (github.com/eduxcode)                         |
|  primitive: CVE-2026-114938                                  |
+--------------------------------------------------------------+
EOF
printf '\033[0m\n'

if [ "$SDE_MODE" = 1 ]; then
  echo "mode: Intel SDE (AVX-512 VBMI emulated) - no cloud, 100% local"
  echo "jdk : $("$J4S_JAVA" -version 2>&1 | head -1)"
  "$J4S_JAVAC" -d "$J4S_BUILD" "$LAB/target/DecodeServer.java" || { echo "build failed"; exit 1; }
  "$SDE" -icx -- "$J4S_JAVA" "${J4S_FLAGS[@]}" \
      -XX:ErrorFile="$EVID/hs_err_%p.log" \
      -Dwarmup=5000 -Dport="$PORT" \
      -cp "$J4S_BUILD" DecodeServer > "$EVID/target.log" 2>&1 &
  TARGET_PID=$!
  trap 'kill "$TARGET_PID" 2>/dev/null' EXIT
else
  echo "mode: Docker (host needs native AVX-512 VBMI)"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker build -q -t "$IMG" ./target >/dev/null || { echo "build failed"; exit 1; }
  docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" \
    -e JAVA_OPTS="-XX:ErrorFile=/app/hs_err_%p.log" "$IMG" >/dev/null
  trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT
fi

echo "waiting for the target to start (short warmup + emulation)..."
for _ in $(seq 1 120); do
  curl -sf -m 2 "$BASE/health" >/dev/null 2>&1 && break
  sleep 1
done

if ! curl -sf -m 2 "$BASE/health" >/dev/null 2>&1; then
  echo "target did not start"
  [ "$SDE_MODE" = 1 ] && tail -20 "$EVID/target.log"
  [ "$SDE_MODE" = 0 ] && docker logs --tail 20 "$NAME" 2>&1
  exit 1
fi

echo "UP: $(curl -s "$BASE/health")"
echo
echo "polling /health every 2s."
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
    echo ">>> TARGET CRASHED (status=$STATE) after $(( $(date +%s) - START ))s"
    echo ">>> last lines:"
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
      echo ">>> hs_err captured: $HS"
      grep -E '^#  SIG|^# JRE version|^# Problematic|^# V  \[' "$HS" | head -6
    fi
    echo
    echo ">>> evidence saved to $EVID"
    break
  fi

  BODY="$(curl -s -m 2 "$BASE/health" 2>/dev/null || true)"
  [ -n "$BODY" ] && printf '[%s] %s\n' "$(date +%H:%M:%S)" "$BODY"
  sleep 2
done
