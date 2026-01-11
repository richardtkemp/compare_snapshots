#!/bin/bash
# Install Git hooks for this repository

HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)"
GIT_HOOKS_DIR="$(git rev-parse --git-dir)/hooks"

echo "Installing Git hooks..."

# Copy pre-commit hook
if [ -f "$HOOKS_DIR/pre-commit" ]; then
    cp "$HOOKS_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit"
    chmod +x "$GIT_HOOKS_DIR/pre-commit"
    echo "✓ Installed pre-commit hook (auto-formats Go code)"
else
    echo "✗ pre-commit hook not found"
    exit 1
fi

echo ""
echo "Hooks installed successfully!"
echo ""
echo "The pre-commit hook will automatically:"
echo "  - Format Go files with gofmt before each commit"
echo "  - Re-stage formatted files automatically"
echo ""
echo "To uninstall, run: rm $GIT_HOOKS_DIR/pre-commit"
