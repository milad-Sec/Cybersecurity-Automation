#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-}"
[[ -z "$TARGET" ]] && { echo "Usage: $0 <target>"; exit 1; }
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUT="nmap_${TARGET//[^a-zA-Z0-9_.-]/_}_${TIMESTAMP}.txt"
nmap -sV -T4 "$TARGET" | tee "$OUT"
echo "Saved: $OUT"
