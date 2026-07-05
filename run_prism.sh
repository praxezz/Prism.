#!/usr/bin/env bash
# Launcher for PRISM - installs dependencies (if missing) and runs the tool.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 -c "import rich, yaml" 2>/dev/null || {
    echo "Installing dependencies..."
    pip3 install -r "$SCRIPT_DIR/requirements.txt"
}

python3 "$SCRIPT_DIR/prism.py" "$@"
