# Git Hooks

This directory contains Git hooks for the compare_snapshots project.

## Available Hooks

### pre-commit

Automatically formats Go code with `gofmt` before each commit.

**What it does:**
- Runs `gofmt -s -w` on all staged `.go` files
- Re-stages the formatted files automatically
- Ensures all committed code follows Go formatting standards

**Benefits:**
- No more formatting failures in CI
- Consistent code style across all contributors
- Automatic - you don't have to remember to run gofmt

## Installation

Run from the project root:

```bash
chmod +x hooks/install.sh
./hooks/install.sh
```

Or manually:

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Uninstallation

```bash
rm .git/hooks/pre-commit
```

## Bypassing the Hook

If you need to commit without running the hook (not recommended):

```bash
git commit --no-verify
```

## Testing the Hook

After installation, try committing an unformatted Go file:

```bash
# Make a formatting change
echo "package main" > test.go
echo "func  foo()  {}" >> test.go  # Extra spaces

# Stage and commit
git add test.go
git commit -m "test"

# The hook will automatically format it before committing
```

## Notes

- The hook only formats files that are staged for commit
- It does not format the entire codebase
- Deleted files are skipped automatically
- The hook exits with code 0 (success) to allow the commit to proceed
