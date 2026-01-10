package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// CreateTestSnapshot creates a temporary directory structure for testing
func CreateTestSnapshot(t *testing.T, name string, files map[string]string) string {
	t.Helper()

	baseDir := t.TempDir()
	snapshotDir := filepath.Join(baseDir, name)

	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		t.Fatalf("Failed to create snapshot directory: %v", err)
	}

	for relPath, content := range files {
		fullPath := filepath.Join(snapshotDir, relPath)
		dir := filepath.Dir(fullPath)

		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}

		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write file %s: %v", fullPath, err)
		}
	}

	return snapshotDir
}

// CreateHardlink creates a hardlink from src to dst
func CreateHardlink(t *testing.T, src, dst string) {
	t.Helper()

	// Ensure destination directory exists
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory %s: %v", dir, err)
	}

	if err := os.Link(src, dst); err != nil {
		t.Fatalf("Failed to create hardlink from %s to %s: %v", src, dst, err)
	}
}

// GetInode returns the inode number for a file
func GetInode(t *testing.T, path string) uint64 {
	t.Helper()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Failed to stat file %s: %v", path, err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("Failed to get syscall.Stat_t for %s", path)
	}

	return stat.Ino
}

// VerifyInodeMap checks if an inode exists and has the expected number of snapshots
func VerifyInodeMap(t *testing.T, inodeMap map[uint64]*FileInfo, expectedInode uint64, expectedSnapshotCount int) {
	t.Helper()

	fileInfo, exists := inodeMap[expectedInode]
	if !exists {
		t.Errorf("Inode %d not found in map", expectedInode)
		return
	}

	actualCount := len(fileInfo.Snapshots)
	if actualCount != expectedSnapshotCount {
		t.Errorf("Inode %d: expected %d snapshots, got %d", expectedInode, expectedSnapshotCount, actualCount)
	}
}

// VerifyEntryStatus checks if a directory entry has the expected status
func VerifyEntryStatus(t *testing.T, entry *DirectoryEntry, expectedStatus FileStatus) {
	t.Helper()

	if entry.Status != expectedStatus {
		t.Errorf("Entry %s: expected status %d, got %d", entry.Name, expectedStatus, entry.Status)
	}
}

// VerifyDirectorySize checks if a directory has the expected total and unique sizes
func VerifyDirectorySize(t *testing.T, dir *DirectoryEntry, expectedTotal, expectedUnique int64) {
	t.Helper()

	if dir.Size != expectedTotal {
		t.Errorf("Directory %s: expected total size %d, got %d", dir.Name, expectedTotal, dir.Size)
	}

	if dir.UniqueSize != expectedUnique {
		t.Errorf("Directory %s: expected unique size %d, got %d", dir.Name, expectedUnique, dir.UniqueSize)
	}
}

// CountEntriesByStatus counts entries in a directory tree by their status
func CountEntriesByStatus(dir *DirectoryEntry, status FileStatus) int {
	count := 0

	for _, child := range dir.Children {
		if !child.IsDir && child.Status == status {
			count++
		}
		if child.IsDir {
			count += CountEntriesByStatus(child, status)
		}
	}

	return count
}

// FindEntryByName finds a child entry by name in a directory
func FindEntryByName(dir *DirectoryEntry, name string) *DirectoryEntry {
	for _, child := range dir.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}
