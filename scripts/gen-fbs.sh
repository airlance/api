#!/usr/bin/env bash
set -euo pipefail

if ! command -v flatc &> /dev/null; then
    echo "error: flatc not found. Install: brew install flatbuffers" >&2
    exit 1
fi

SCHEMA="proto/schema.fbs"
OUT_DIR="internal/protocol/generated"

mkdir -p "$OUT_DIR"
flatc --go -o "$OUT_DIR" "$SCHEMA"

echo "generated Go code from $SCHEMA -> $OUT_DIR"
