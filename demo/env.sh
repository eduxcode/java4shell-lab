#!/usr/bin/env bash
# Resolve o modo de execucao do laboratorio.
#   SDE_MODE=1 -> Intel SDE local (emula AVX-512 VBMI) + JDK extraido do Docker
#   SDE_MODE=0 -> Docker (host precisa de AVX-512 nativo)
#
# Uso: source demo/env.sh   (nao execute diretamente)
# Autor do harness: eduxcode (github.com/eduxcode)
# Primitiva: CVE-2026-114938 / Quang Luong - Calif.io

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$LAB/demo/.tools"
J4S_BUILD="$LAB/demo/.build"
SDE="$TOOLS/sde/sde64"
J4S_JAVA="$TOOLS/jdk/bin/java"
J4S_JAVAC="$TOOLS/jdk/bin/javac"
J4S_FLAGS=(-Xbatch -XX:-TieredCompilation -XX:CompileThreshold=500 -XX:UseAVX=3)

SDE_MODE=0
if [ -x "$SDE" ] && [ -x "$J4S_JAVA" ]; then
  SDE_MODE=1
fi
