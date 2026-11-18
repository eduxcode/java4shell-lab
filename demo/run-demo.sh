#!/usr/bin/env bash
# Abre os dois paineis em tmux: alvo a esquerda, atacante a direita.
# Autor do harness: eduxcode (github.com/eduxcode)
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB"
source "$LAB/demo/env.sh"

if [ "$SDE_MODE" != 1 ]; then
  echo "SDE nao instalado: rode ./demo/setup-sde.sh uma vez."
  echo "Sem SDE, o modo Docker exige AVX-512 nativo e nao vai reproduzir aqui."
  echo "Alternativa manual:"
  echo "  T1: ./demo/target.sh"
  echo "  T2: ./demo/attacker.sh"
  exit 1
fi

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux nao encontrado. Use dois terminais:"
  echo "  T1: ./demo/target.sh"
  echo "  T2: ./demo/attacker.sh"
  exit 1
fi

S="j4s-demo"
tmux kill-session -t "$S" 2>/dev/null || true

tmux new-session -d -s "$S" -x 200 -y 50 -c "$LAB" "./demo/target.sh"
tmux set-option -t "$S" remain-on-exit on
tmux split-window -h -t "$S" -c "$LAB" "./demo/attacker.sh"
tmux select-pane -t "$S:0.1"
tmux attach -t "$S"
