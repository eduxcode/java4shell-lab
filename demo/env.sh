#!/usr/bin/env bash
# Resolves the lab execution mode.
#   SDE_MODE=1 -> local Intel SDE (emulates AVX-512 VBMI) + JDK extracted from Docker
#   SDE_MODE=0 -> Docker (host needs native AVX-512)
#
# Usage: source demo/env.sh   (do not execute directly)
# Lab author: eduxcode (github.com/eduxcode)
# Primitive: CVE-2026-114938 / Quang Luong - Calif.io

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
