#!/usr/bin/env bash
# Packages the lab to copy to an AVX-512 instance.
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
echo "package: $OUT ($(du -h "$OUT" | cut -f1))"
tar tzf "$OUT" | sed -n '1,12p'
