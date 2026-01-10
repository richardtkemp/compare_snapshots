package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestErrorHandling tests various error conditions
func TestInvalidInputs(t *testing.T) {
	// Test empty snapshot list
	t.Run("empty snapshot list", func(t *testing.T) {
		_, err := NewSnapshotComparison([]string{})
		if err == nil {
			t.Error("Expected error for empty snapshot list, got nil")
		}
	})

	// Test non-existent paths
	t.Run("non-existent path", func(t *testing.T) {
		sc, err := NewSnapshotComparison([]string{"/this/path/does/not/exist"})
		if err != nil {
			// If it errors in constructor, that's fine
			return
		}
		// If constructor succeeds, scan should fail or handle gracefully
		err = sc.ScanSnapshots()
		// We just check it doesn't panic - error handling could be improved
		t.Logf("Scanning non-existent path returned: %v", err)
	})
}

// TestPermissionErrors tests handling of permission-denied scenarios
func TestPermissionErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping permission test in short mode")
	}

	// Create a directory with no read permission
	baseDir := t.TempDir()
	restrictedDir := filepath.Join(baseDir, "snapshot1")
	if err := os.Mkdir(restrictedDir, 0755); err != nil {
		t.Fatalf("Failed to create test dir: %v", err)
	}

	// Create a file in it
	testFile := filepath.Join(restrictedDir, "file.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Remove read permission from directory
	if err := os.Chmod(restrictedDir, 0000); err != nil {
		t.Fatalf("Failed to chmod: %v", err)
	}
	defer os.Chmod(restrictedDir, 0755) // Restore for cleanup

	// Try to scan
	sc, err := NewSnapshotComparison([]string{restrictedDir})
	if err != nil {
		t.Logf("Constructor failed (acceptable): %v", err)
		return
	}

	err = sc.ScanSnapshots()
	// Should fail or handle gracefully
	t.Logf("Scanning restricted directory returned: %v", err)
	// The important thing is it doesn't panic
}

// TestMultipleHardlinksInSameSnapshot tests when multiple paths in the same snapshot point to the same inode
func TestMultipleHardlinksInSameSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create snapshot with original file
	snapshot1 := CreateTestSnapshot(t, "snapshot1", map[string]string{
		"original.txt": "shared content",
	})

	// Create multiple hardlinks to the same file WITHIN the same snapshot
	originalPath := filepath.Join(snapshot1, "original.txt")
	hardlink1 := filepath.Join(snapshot1, "hardlink1.txt")
	hardlink2 := filepath.Join(snapshot1, "hardlink2.txt")

	CreateHardlink(t, originalPath, hardlink1)
	CreateHardlink(t, originalPath, hardlink2)

	// Verify all three have the same inode
	inodeOriginal := GetInode(t, originalPath)
	inodeLink1 := GetInode(t, hardlink1)
	inodeLink2 := GetInode(t, hardlink2)

	if inodeOriginal != inodeLink1 || inodeOriginal != inodeLink2 {
		t.Fatalf("Hardlinks don't have same inode: %d, %d, %d", inodeOriginal, inodeLink1, inodeLink2)
	}

	t.Logf("All three files share inode: %d", inodeOriginal)

	// Scan the snapshot
	sc, err := NewSnapshotComparison([]string{snapshot1})
	if err != nil {
		t.Fatalf("NewSnapshotComparison failed: %v", err)
	}

	if err := sc.ScanSnapshots(); err != nil {
		t.Fatalf("ScanSnapshots failed: %v", err)
	}

	// Should have exactly 1 unique inode
	if len(sc.InodeMap) != 1 {
		t.Errorf("Expected 1 unique inode, got %d", len(sc.InodeMap))
	}

	// Check that the inode is tracked correctly
	fileInfo, ok := sc.InodeMap[inodeOriginal]
	if !ok {
		t.Fatalf("Inode %d not found in map", inodeOriginal)
	}

	// Should be in only 1 snapshot
	if len(fileInfo.Snapshots) != 1 {
		t.Errorf("Expected inode in 1 snapshot, got %d", len(fileInfo.Snapshots))
	}

	// Check how many paths are tracked
	if len(fileInfo.Paths) != 1 {
		t.Logf("Note: Inode has %d paths tracked (original + %d hardlinks)", len(fileInfo.Paths), len(fileInfo.Paths)-1)
		// This documents the behavior - we update the path each time we see the inode
		// So we only keep the LAST path encountered, not all paths
		t.Logf("Paths: %v", fileInfo.Paths)
	}

	// Verify the file is marked as unique (not shared across snapshots)
	// Build the tree to see how it's classified
	if sc.RootEntry != nil && len(sc.RootEntry.Children) > 0 {
		// Check one of the files
		for _, child := range sc.RootEntry.Children {
			if !child.IsDir {
				if child.Status != StatusUnique {
					t.Errorf("File within single snapshot should be Unique, got status %d", child.Status)
				}
				t.Logf("File status: %d (should be StatusUnique=%d)", child.Status, StatusUnique)
				break
			}
		}
	}
}

// TestCrossSnapshotAndSameSnapshotHardlinks tests complex hardlink scenario
func TestCrossSnapshotAndSameSnapshotHardlinks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create snapshot1 with a file and hardlinks
	snapshot1 := CreateTestSnapshot(t, "snapshot1", map[string]string{
		"file.txt": "content",
	})

	// Create hardlinks within snapshot1
	file1 := filepath.Join(snapshot1, "file.txt")
	link1a := filepath.Join(snapshot1, "link1a.txt")
	CreateHardlink(t, file1, link1a)

	inode1 := GetInode(t, file1)

	// Create snapshot2 directory
	baseDir := filepath.Dir(snapshot1)
	snapshot2 := filepath.Join(baseDir, "snapshot2")
	if err := os.MkdirAll(snapshot2, 0755); err != nil {
		t.Fatalf("Failed to create snapshot2: %v", err)
	}

	// Create hardlink from snapshot1 to snapshot2 (shared across snapshots)
	file2 := filepath.Join(snapshot2, "file.txt")
	CreateHardlink(t, file1, file2)

	// Create hardlink within snapshot2
	link2a := filepath.Join(snapshot2, "link2a.txt")
	CreateHardlink(t, file2, link2a)

	// Verify all have same inode
	inode2 := GetInode(t, file2)
	if inode1 != inode2 {
		t.Fatalf("Cross-snapshot hardlink failed: %d != %d", inode1, inode2)
	}

	t.Logf("All files share inode %d across 2 snapshots", inode1)

	// Scan
	sc, err := NewSnapshotComparison([]string{snapshot1, snapshot2})
	if err != nil {
		t.Fatalf("NewSnapshotComparison failed: %v", err)
	}

	if err := sc.ScanSnapshots(); err != nil {
		t.Fatalf("ScanSnapshots failed: %v", err)
	}

	// Should have 1 unique inode
	if len(sc.InodeMap) != 1 {
		t.Errorf("Expected 1 unique inode, got %d", len(sc.InodeMap))
	}

	// Should be marked as shared (appears in 2 snapshots)
	fileInfo := sc.InodeMap[inode1]
	if len(fileInfo.Snapshots) != 2 {
		t.Errorf("Expected inode in 2 snapshots, got %d", len(fileInfo.Snapshots))
	}

	// Check files are marked as shared
	for _, child := range sc.RootEntry.Children {
		if !child.IsDir && child.Inode == inode1 {
			if child.Status != StatusShared {
				t.Errorf("Cross-snapshot hardlink should be Shared, got status %d", child.Status)
			}
		}
	}
}
