#!/bin/bash
# PostToolUse hook: auto-commit project files on Write/Edit
# Modeled after GitAutoSync — check status, stage, commit.
# No stdin parsing needed — just commit whatever changed.

PROJECT_DIR="/Users/hogers/Projects/claude-on-blackberry"
DEBOUNCE_FILE="/tmp/.bb-autocommit-ts"
DEBOUNCE_SECONDS=30

# Debounce: skip if last commit was < 30s ago
if [ -f "$DEBOUNCE_FILE" ]; then
    last_ts=$(cat "$DEBOUNCE_FILE" 2>/dev/null || echo 0)
    now_ts=$(date +%s)
    elapsed=$((now_ts - last_ts))
    if [ "$elapsed" -lt "$DEBOUNCE_SECONDS" ]; then
        echo '{}'
        exit 0
    fi
fi

# Check for changes
status=$(git -C "$PROJECT_DIR" status --porcelain 2>/dev/null)
if [ -z "$status" ]; then
    echo '{}'
    exit 0
fi

# Stage all changes, commit
git -C "$PROJECT_DIR" add -A 2>/dev/null
git -C "$PROJECT_DIR" commit -m "auto-sync: $(date '+%Y-%m-%d %H:%M:%S')

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>" 2>/dev/null

if [ $? -eq 0 ]; then
    date +%s > "$DEBOUNCE_FILE"
    cat <<'HOOKEOF'
{
  "additionalContext": "Auto-committed project changes."
}
HOOKEOF
else
    echo '{}'
fi
