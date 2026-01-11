#!/bin/bash
# Pre-commit test script for compare_snapshots
# Run this before committing to ensure code quality

set -e  # Exit on any error

echo "============================================"
echo "Running pre-commit checks..."
echo "============================================"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed"
    exit 1
fi

# Format check
echo "📝 Running go fmt..."
UNFORMATTED=$(gofmt -l .)
if [ -n "$UNFORMATTED" ]; then
    echo "❌ Code needs formatting:"
    echo "$UNFORMATTED"
    echo ""
    echo "Run: go fmt ./..."
    exit 1
fi
echo "✓ Code formatting looks good"
echo ""

# Vet
echo "🔍 Running go vet..."
if ! go vet ./...; then
    echo "❌ go vet found issues"
    exit 1
fi
echo "✓ go vet passed"
echo ""

# Unit tests (when they exist)
echo "🧪 Running unit tests..."
if ! go test -v -short ./... 2>&1; then
    echo "❌ Unit tests failed"
    exit 1
fi
echo "✓ Unit tests passed"
echo ""

# Integration tests (when they exist)
echo "🧪 Running integration tests..."
if ! go test -v ./... 2>&1; then
    echo "❌ Integration tests failed"
    exit 1
fi
echo "✓ Integration tests passed"
echo ""

# Build
echo "🔨 Building binary..."
if ! go build -o compare_snapshots; then
    echo "❌ Build failed"
    exit 1
fi
echo "✓ Build successful"
echo ""

# Smoke test
echo "💨 Running smoke test..."
if ./compare_snapshots 2>&1 | grep -q "Usage:"; then
    echo "✓ Binary runs and shows usage"
else
    echo "⚠️  Binary runs but may have issues"
fi
echo ""

echo "============================================"
echo "✅ All checks passed!"
echo "============================================"
echo ""
echo "You can now commit your changes."
