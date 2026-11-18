#!/usr/bin/env bash
# Helper: roda um comando sh dentro de uma imagem JDK.
set -euo pipefail
IMG="$1"; shift
exec docker run --rm --entrypoint sh "$IMG" -c "$*"
