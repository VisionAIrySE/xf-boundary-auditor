#!/usr/bin/env bash
set -euo pipefail

AUDITOR_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK_INPUT="$(cat)"  # read stdin once

# Extract tool_name (stdin contract is JSON)
TOOL_NAME="$(
  printf '%s' "$HOOK_INPUT" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("tool_name",""))' 2>/dev/null || true
)"

if [[ "$TOOL_NAME" != "Edit" && "$TOOL_NAME" != "Write" ]]; then
  exit 0
fi

python3 "$AUDITOR_DIR/auditor.py" "$HOOK_INPUT"
