#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-secure-range-proof-system.zip}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

rm -f "${OUT}"
zip -r "${OUT}" . \
  -x "build/*" \
  -x "client/node_modules/*" \
  -x "client/dist/*" \
  -x "client/.tsx-cache/*"

echo "Wrote ${OUT}"

