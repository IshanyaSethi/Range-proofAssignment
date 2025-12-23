#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PROTO_DIR="${ROOT_DIR}/proto"
NANOPB_DIR="${ROOT_DIR}/server/third_party/nanopb_src"
GEN_OUT="${ROOT_DIR}/server/generated"

PLUGIN="${NANOPB_DIR}/generator/protoc-gen-nanopb"
INCLUDE_GOOGLE="${NANOPB_DIR}/generator/proto"

mkdir -p "${GEN_OUT}"

protoc \
  -I"${PROTO_DIR}" \
  -I"${INCLUDE_GOOGLE}" \
  --plugin=protoc-gen-nanopb="${PLUGIN}" \
  --nanopb_out="${GEN_OUT}" \
  "${PROTO_DIR}/secure_range_proof.proto"

echo "Generated nanopb files into ${GEN_OUT}"

