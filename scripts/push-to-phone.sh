#!/bin/bash
# Push a file to the BlackBerry Priv's Termux home directory
# Usage: ./push-to-phone.sh <local-file> [remote-subpath]

TERMUX_HOME="/data/data/com.termux/files/home"

if [ -z "$1" ]; then
    echo "Usage: $0 <local-file> [remote-subpath]"
    echo "Example: $0 node alpine/"
    exit 1
fi

LOCAL_FILE="$1"
REMOTE_SUBPATH="${2:-}"

if [ ! -f "$LOCAL_FILE" ]; then
    echo "Error: File '$LOCAL_FILE' not found"
    exit 1
fi

echo "Pushing $LOCAL_FILE to $TERMUX_HOME/$REMOTE_SUBPATH"
adb push "$LOCAL_FILE" "$TERMUX_HOME/$REMOTE_SUBPATH"
