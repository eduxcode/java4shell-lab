#!/usr/bin/env bash
# Empacota o laboratorio para copiar a uma instancia com AVX-512.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$LAB/deploy/java4shell-lab.tgz"
cd "$LAB"
tar czf "$OUT" \
  --exclude='deploy/evidence' \
  --exclude='demo/evidence' \
  --exclude='demo/.tools' \
  --exclude='demo/.build' \
  --exclude='deploy/java4shell-lab.tgz' \
  --exclude='.terraform' \
  --exclude='*.class' \
  README.md CREDITS.md run-lab.sh target poc demo deploy
echo "pacote: $OUT ($(du -h "$OUT" | cut -f1))"
tar tzf "$OUT" | sed -n '1,12p'
