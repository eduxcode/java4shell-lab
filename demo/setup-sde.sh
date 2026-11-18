#!/usr/bin/env bash
# Prepara o modo local sem AWS: Intel SDE + JDK 17.0.21 extraido da imagem Docker.
# Roda uma vez; depois use ./demo/run-demo.sh.
#
# Autor do harness: eduxcode (github.com/eduxcode)
# Primitiva: CVE-2026-114938 / Quang Luong - Calif.io
set -euo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB"
source "$LAB/demo/env.sh"

mkdir -p "$TOOLS" "$J4S_BUILD"

SDE_URL="https://downloadmirror.intel.com/924984/sde-external-10.13.1-2026-07-28-lin.tar.xz"
SDE_DIR="sde-external-10.13.1-2026-07-28-lin"

if [ ! -x "$SDE" ]; then
  echo "== baixando Intel SDE 10.13.1 (37 MB) =="
  curl -fL --retry 3 -o "$TOOLS/sde.tar.xz" "$SDE_URL"
  tar xf "$TOOLS/sde.tar.xz" -C "$TOOLS"
  ln -sfn "$TOOLS/$SDE_DIR" "$TOOLS/sde"
fi
echo "SDE: $($SDE -version 2>&1 | head -1)"

if [ ! -x "$J4S_JAVA" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker nao encontrado. Instale o Docker ou baixe o Temurin 17.0.21 e" >&2
    echo "coloque o JDK em $TOOLS/jdk." >&2
    exit 1
  fi
  echo "== extraindo JDK 17.0.21_9 da imagem eclipse-temurin =="
  docker rm -f j4s-jdk-setup >/dev/null 2>&1 || true
  docker create --name j4s-jdk-setup eclipse-temurin:17.0.21_9-jdk >/dev/null
  docker cp j4s-jdk-setup:/opt/java/openjdk "$TOOLS/jdk" >/dev/null
  docker rm -f j4s-jdk-setup >/dev/null
fi
echo "JDK: $($J4S_JAVA -version 2>&1 | head -1)"

echo "== compilando =="
"$J4S_JAVAC" -d "$J4S_BUILD" \
  "$LAB/target/DecodeServer.java" \
  "$LAB/poc/Oracle.java" \
  "$LAB/poc/MaskUnderflow.java" \
  "$LAB/poc/Base64Trigger.java"
echo "build: $J4S_BUILD"

echo "== verificando emulacao =="
"$SDE" -icx -- "$J4S_JAVA" -XX:+PrintFlagsFinal -version 2>/dev/null | grep -E 'UseAVX|UseBASE64Intrinsics' || true

echo
echo "pronto. grave com:"
echo "  ./demo/run-demo.sh          # dois paineis no tmux"
echo "  ./demo/record.sh            # idem, gravando com asciinema"
