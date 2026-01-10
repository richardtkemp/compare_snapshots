# Testing Plan for compare_snapshots

## Overview
This document outlines the testing strategy for the compare_snapshots tool, including unit tests, integration tests, and CI/CD integration.

## Test Structure

### 1. Unit Tests (`main_test.go`)

**Target Functions:**
- `formatSize(size int64)` - Size formatting logic
- `determineFileStatus(fileInfo *FileInfo)` - Shared vs Unique status logic
- `calculateDirectorySize(dir *DirectoryNode)` - Recursive size calculation
- Inode map population logic

**Test Cases:**
```go
TestFormatSize:
  - 0 bytes → "0 B"
  - 1023 bytes → "1023 B"
  - 1024 bytes → "1.0 KiB"
  - 1048576 bytes → "1.0 MiB"
  - Large values (GiB, TiB)

TestDetermineFileStatus:
  - Single snapshot → Unique
  - Multiple snapshots, same inode → Shared
  - Multiple snapshots, different inodes → (should be Unique, currently not handled)

TestCalculateDirectorySize:
  - Empty directory → 0 size
  - Directory with files → sum of file sizes
  - Nested directories → recursive sum
  - Mixed shared/unique files → correct total and unique sizes
```

### 2. Integration Tests (`integration_test.go`)

**Test Scenarios:**

#### Test 1: Basic Hardlink Detection
```
Setup:
  snapshot1/
    file1.txt (inode 100, 1KB)
    file2.txt (inode 101, 2KB)
  snapshot2/
    file1.txt (hardlink to inode 100, 1KB)
    file3.txt (inode 102, 3KB)

Expected Results:
  - Total size: 6KB (1+2+1+3)
  - Unique size: 5KB (1+2+3, file1.txt counted once)
  - file1.txt status: Shared
  - file2.txt, file3.txt status: Unique
```

#### Test 2: Directory Structures
```
Setup:
  snapshot1/
    dir1/file.txt (inode 200, 5KB)
    dir2/file.txt (inode 201, 3KB)
  snapshot2/
    dir1/file.txt (hardlink to inode 200, 5KB)
    dir2/file.txt (inode 202, 3KB)

Expected Results:
  - dir1 status: Shared (contains shared file)
  - dir2 status: Unique (different inodes)
  - Correct size aggregation
```

#### Test 3: Three-Way Snapshots
```
Setup:
  snapshot1/shared.txt (inode 300)
  snapshot2/shared.txt (hardlink to inode 300)
  snapshot3/shared.txt (hardlink to inode 300)

Expected Results:
  - shared.txt appears in all 3 snapshots
  - Unique size: counted once
  - Status: Shared
```

#### Test 4: Empty Snapshots
```
Setup:
  snapshot1/ (empty directory)
  snapshot2/file.txt (1KB)

Expected Results:
  - No errors
  - Total size: 1KB
  - Unique size: 1KB
```

#### Test 5: Symlink Handling (Edge Case)
```
Setup:
  snapshot1/
    file.txt (regular file, 1KB)
    link.txt -> file.txt (symlink)

Expected Results:
  - Should NOT follow symlink
  - Should NOT count twice
  - Should NOT infinite loop on circular symlinks
```

#### Test 6: Permission Errors
```
Setup:
  snapshot1/
    accessible.txt (readable)
    restricted.txt (no read permission)

Expected Results:
  - Process accessible files
  - Skip restricted files gracefully
  - No crash
```

### 3. Test Utilities (`testutil.go`)

**Helper Functions:**
```go
// CreateTestSnapshot creates a temporary directory structure
func CreateTestSnapshot(t *testing.T, files map[string]string) string

// CreateHardlink creates a hardlink between two files
func CreateHardlink(t *testing.T, src, dst string)

// GetInode returns the inode number for a file
func GetInode(t *testing.T, path string) uint64

// VerifyInodeMap checks if inodes are correctly mapped
func VerifyInodeMap(t *testing.T, inodeMap map[uint64][]*FileInfo, expected map[uint64]int)

// CleanupTestSnapshots removes test directories
func CleanupTestSnapshots(t *testing.T, paths ...string)
```

## Manual Testing Workflow

### Pre-commit Git Hook (Recommended)

Install the automatic formatting hook:
```bash
./hooks/install.sh
```

This will automatically format Go files before each commit, preventing formatting issues.

### Pre-commit Testing Script (`test.sh`)
```bash
#!/bin/bash
set -e

echo "Running go fmt..."
go fmt ./...

echo "Running go vet..."
go vet ./...

echo "Running unit tests..."
go test -v -short ./...

echo "Running integration tests..."
go test -v ./...

echo "Building binary..."
go build -o compare_snapshots

echo "Running smoke test..."
./compare_snapshots --help > /dev/null 2>&1 || true

echo "All checks passed!"
```

### Usage:
```bash
# Install pre-commit hook (one time, recommended)
./hooks/install.sh

# Manual testing before committing
chmod +x test.sh
./test.sh

# Or run individual steps
go test -v ./...                    # All tests
go test -v -short ./...             # Unit tests only
go test -v -run TestHardlinks ./... # Specific test
```

## CI/CD Integration

### Updated `.github/workflows/go.yml`
```yaml
name: Go

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.22'

      - name: Format check
        run: |
          if [ "$(gofmt -s -l . | wc -l)" -gt 0 ]; then
            echo "Code needs formatting:"
            gofmt -s -d .
            exit 1
          fi

      - name: Vet
        run: go vet ./...

      - name: Unit Tests
        run: go test -v -short -race -coverprofile=coverage.txt -covermode=atomic ./...

      - name: Integration Tests
        run: go test -v -race ./...

      - name: Build
        run: go build -o ./compare_snapshots

      - name: Smoke Test
        run: |
          ./compare_snapshots --help || true
          # Test returns non-zero without args, which is expected

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.txt

  release:
    needs: test  # Only run if tests pass
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.22'

      - name: Build
        run: go build -o ./compare_snapshots

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          tag_name: v${{ github.run_number }}
          name: Release v${{ github.run_number }}
          draft: false
          prerelease: false
          files: ./compare_snapshots
```

## Test Coverage Goals

- **Unit test coverage:** 70%+ of non-UI code
- **Integration tests:** All major use cases covered
- **Edge cases:** Symlinks, permissions, empty directories
- **Performance:** Tests complete in <10 seconds

## Implementation Order

1. **Phase 1:** Create test utilities and basic unit tests
   - `testutil.go` with helper functions
   - `TestFormatSize`
   - `TestDetermineFileStatus`

2. **Phase 2:** Add integration tests
   - `TestBasicHardlinkDetection`
   - `TestDirectoryStructures`
   - `TestThreeWaySnapshots`

3. **Phase 3:** Add edge case tests
   - `TestEmptySnapshots`
   - `TestSymlinkHandling`
   - `TestPermissionErrors`

4. **Phase 4:** CI/CD integration
   - Update GitHub Actions workflow
   - Add pre-commit script
   - Add coverage reporting

5. **Phase 5:** Documentation
   - Update README with testing instructions
   - Document test execution in CONTRIBUTING.md

## Notes

- Tests should be platform-aware (Unix/Linux vs Windows syscalls)
- Use `t.TempDir()` for automatic cleanup
- Use `testing.Short()` to skip slow integration tests
- Consider using `github.com/stretchr/testify` for assertions (optional)
- Mock the TUI for testing non-interactive logic
