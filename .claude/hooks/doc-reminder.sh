#!/bin/bash
# PostToolUse hook: remind to document and commit every 10 Bash calls
# Simple counter-based trigger — no time check needed.

PROJECT_DIR="/Users/hogers/Projects/claude-on-blackberry"
STATE_FILE="/tmp/.bb-exploit-doc-reminder"
TRIGGER_EVERY=10

# Count tool calls since last reminder
call_count=0
if [ -f "$STATE_FILE" ]; then
    call_count=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
fi
call_count=$((call_count + 1))
echo "$call_count" > "$STATE_FILE"

if [ "$call_count" -ge "$TRIGGER_EVERY" ]; then
    echo 0 > "$STATE_FILE"

    has_changes=$(git -C "$PROJECT_DIR" status --porcelain 2>/dev/null | head -1)
    if [ -n "$has_changes" ]; then
        change_note="There are uncommitted changes in the working tree."
    else
        change_note="Working tree is clean, but recent findings may need documenting."
    fi

    cat <<HOOKEOF
{
  "additionalContext": "DOCUMENTATION CHECKPOINT (${call_count} Bash calls): ${change_note} Before continuing: (1) Document findings in docs/ (2) Update README.md if milestones reached (3) Stage, commit, and push."
}
HOOKEOF
else
    echo '{}'
fi
