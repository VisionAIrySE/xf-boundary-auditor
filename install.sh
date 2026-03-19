#!/usr/bin/env bash
set -euo pipefail

# XF Boundary Auditor installer for Claude Code
# - Installs hook + skill into ~/.claude
# - Registers PreToolUse hook in ~/.claude/settings.json (merge-safe)

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDE_DIR="${CLAUDE_DIR:-$HOME/.claude}"
SKILL_DIR="$CLAUDE_DIR/skills/xf-audit"
HOOKS_DIR="$CLAUDE_DIR/hooks"
SETTINGS_JSON="$CLAUDE_DIR/settings.json"

mkdir -p "$SKILL_DIR" "$HOOKS_DIR"

# 1) Copy skill
cp -f "$SRC_DIR/skill.md" "$SKILL_DIR/skill.md"

# 2) Copy hook
cp -f "$SRC_DIR/hook.sh" "$HOOKS_DIR/xf-boundary-auditor.sh"
chmod +x "$HOOKS_DIR/xf-boundary-auditor.sh"

# 3) Merge hook registration into settings.json
python3 - <<'PY'
import json
import os

claude_dir = os.path.expanduser(os.environ.get('CLAUDE_DIR', '~/.claude'))
settings_path = os.path.join(claude_dir, 'settings.json')

hook_command = os.path.join(claude_dir, 'hooks', 'xf-boundary-auditor.sh')

try:
    with open(settings_path, 'r', encoding='utf-8') as f:
        settings = json.load(f)
except Exception:
    settings = {}

hooks = settings.setdefault('hooks', {})
pre = hooks.setdefault('PreToolUse', [])

entry = {
    "matcher": "",
    "hooks": [{"type": "command", "command": hook_command}],
}

def is_dup(e):
    try:
        cmd = (e.get('hooks') or [{}])[0].get('command', '')
        return cmd.endswith('xf-boundary-auditor.sh')
    except Exception:
        return False

if not any(is_dup(e) for e in pre):
    pre.append(entry)

os.makedirs(os.path.dirname(settings_path), exist_ok=True)
with open(settings_path, 'w', encoding='utf-8') as f:
    json.dump(settings, f, indent=2)
PY

cat <<EOF

XF Boundary Auditor installed.
- Skill:   $SKILL_DIR/skill.md
- Hook:    $HOOKS_DIR/xf-boundary-auditor.sh
- Settings: $SETTINGS_JSON (PreToolUse registered)

IMPORTANT: Start a NEW Claude Code session to activate hooks.
EOF
