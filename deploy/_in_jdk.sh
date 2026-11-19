#!/usr/bin/env bash
# Helper: runs an sh command inside a JDK image.
set -euo pipefail
IMG="$1"; shift
exec docker run --rm --entrypoint sh "$IMG" -c "$*"
