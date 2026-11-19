#!/usr/bin/env bash
# Opens the two tmux panes: target on the left, attacker on the right.
# Lab author: eduxcode (github.com/eduxcode)
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB"
source "$LAB/demo/env.sh"

if [ "$SDE_MODE" != 1 ]; then
  echo "SDE not installed: run ./demo/setup-sde.sh once."
  echo "Without SDE, Docker mode requires native AVX-512 and will not reproduce here."
  echo "Manual alternative:"
  echo "  T1: ./demo/target.sh"
  echo "  T2: ./demo/attacker.sh"
  exit 1
fi

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux not found. Use two terminals:"
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
