#!/usr/bin/env bash
# Grava a demo em dois paineis com asciinema.
# Ao terminar, saia do tmux com Ctrl-b d (o asciinema encerra a gravacao).
#
# Uso: ./demo/record.sh [arquivo.cast]
# Autor do harness: eduxcode (github.com/eduxcode)
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB"

command -v asciinema >/dev/null 2>&1 || {
  echo "asciinema nao instalado. Use OBS Studio ou instale: sudo apt install asciinema" >&2
  exit 1
}
[ -x ./demo/.tools/sde/sde64 ] || {
  echo "rode ./demo/setup-sde.sh primeiro" >&2
  exit 1
}

OUT="${1:-java4shell-eduxcode.cast}"
exec asciinema rec "$OUT" \
  --title "CVE-2026-114938 - corrupcao de heap reproduzida (eduxcode)" \
  --command "./demo/run-demo.sh"
