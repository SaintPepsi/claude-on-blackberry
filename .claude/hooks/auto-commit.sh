#!/bin/bash
# PostToolUse hook: auto-commit when files in this project are written/edited
# Fires on Write and Edit tools, stages the changed file, and commits.

PROJECT_DIR="/Users/hogers/Projects/claude-on-blackberry"

# Read the tool input from stdin
INPUT=$(cat)

# Extract the file path from the tool input
FILE_PATH=$(echo "$INPUT" | grep -o '"file_path"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"file_path"[[:space:]]*:[[:space:]]*"//;s/"$//')

# If no file path found, nothing to do
if [ -z "$FILE_PATH" ]; then
    echo '{}'
    exit 0
fi

# Only auto-commit files within the project directory
case "$FILE_PATH" in
    "$PROJECT_DIR"/*)
        ;;
    *)
        echo '{}'
        exit 0
        ;;
esac

# Get relative path for commit message
REL_PATH="${FILE_PATH#$PROJECT_DIR/}"

# Check if the file has actual changes to commit
cd "$PROJECT_DIR" || exit 0
CHANGES=$(git diff --name-only -- "$REL_PATH" 2>/dev/null)
UNTRACKED=$(git ls-files --others --exclude-standard -- "$REL_PATH" 2>/dev/null)

if [ -n "$CHANGES" ] || [ -n "$UNTRACKED" ]; then
    git add "$REL_PATH" 2>/dev/null
    git commit -m "Auto-commit: update $REL_PATH

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>" 2>/dev/null

    if [ $? -eq 0 ]; then
        cat <<HOOKEOF
{
  "additionalContext": "Auto-committed: $REL_PATH"
}
HOOKEOF
    else
        echo '{}'
    fi
else
    echo '{}'
fi
