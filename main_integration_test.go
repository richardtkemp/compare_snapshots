package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ============================================================================
// Hardlink Detection Tests
// ============================================================================

// TestBasicHardlinkDetection tests that hardlinked files are correctly identified
func TestBasicHardlinkDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create snapshot1 with two files
	snapshot1 := CreateTestSnapshot(t, "snapshot1", map[string]string{
		"file1.txt": "content of file1",
		"file2.txt": "content of file2 with more data",
	})

	// Create snapshot2 directory
	baseDir := filepath.Dir(snapshot1)
	snapshot2 := filepath.Join(baseDir, "snapshot2")
	if err := os.MkdirAll(snapshot2, 0755); err != nil {
		t.Fatalf("Failed to create snapshot2: %v", err)
	}

	// Create hardlink to file1 in snapshot2
	file1Path := filepath.Join(snapshot1, "file1.txt")
	CreateHardlink(t, file1Path, filepath.Join(snapshot2, "file1.txt"))

	// Create unique file in snapshot2
	file3Path := filepath.Join(snapshot2, "file3.txt")
	if err := os.WriteFile(file3Path, []byte("content of file3 unique"), 0644); err != nil {
		t.Fatalf("Failed to create file3: %v", err)
	}

	// Get inodes for verification
	inode1 := GetInode(t, file1Path)
	inode2 := GetInode(t, filepath.Join(snapshot1, "file2.txt"))
	inode3 := GetInode(t, file3Path)

	// Verify that hardlinked files have the same inode
	inode1_snapshot2 := GetInode(t, filepath.Join(snapshot2, "file1.txt"))
	if inode1 != inode1_snapshot2 {
		t.Errorf("Hardlinked files have different inodes: %d vs %d", inode1, inode1_snapshot2)
	}

	t.Logf("Inode1 (hardlinked): %d", inode1)
	t.Logf("Inode2 (unique to snap1): %d", inode2)
	t.Logf("Inode3 (unique to snap2): %d", inode3)

	// Run the scanner
	sc, err := NewSnapshotComparison([]string{snapshot1, snapshot2})
	if err != nil {
		t.Fatalf("NewSnapshotComparison failed: %v", err)
	}

	if err := sc.ScanSnapshots(); err != nil {
		t.Fatalf("ScanSnapshots failed: %v", err)
	}

	// Verify inode map
	if len(sc.InodeMap) == 0 {
		t.Fatal("InodeMap is empty after scan")
	}

	t.Logf("Found %d unique inodes", len(sc.InodeMap))

	// Check if file1 appears in both snapshots
	if fileInfo, ok := sc.InodeMap[inode1]; ok {
		t.Logf("Inode %d snapshots: %v", inode1, fileInfo.Snapshots)
		if len(fileInfo.Snapshots) != 2 {
			t.Errorf("Expected file1 to be in 2 snapshots, got %d", len(fileInfo.Snapshots))
		}
	} else {
		t.Errorf("Inode %d not found in InodeMap", inode1)
	}

	// Check unique files
	if fileInfo, ok := sc.InodeMap[inode2]; ok {
		if len(fileInfo.Snapshots) != 1 {
			t.Errorf("Expected file2 to be in 1 snapshot, got %d", len(fileInfo.Snapshots))
		}
	}

	if fileInfo, ok := sc.InodeMap[inode3]; ok {
		if len(fileInfo.Snapshots) != 1 {
			t.Errorf("Expected file3 to be in 1 snapshot, got %d", len(fileInfo.Snapshots))
		}
	}
}

// TestThreeWaySnapshots tests file shared across three snapshots
func TestThreeWaySnapshots(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create snapshot1 with a file
	snapshot1 := CreateTestSnapshot(t, "snapshot1", map[string]string{
		"shared.txt": "shared content across all snapshots",
	})

	baseDir := filepath.Dir(snapshot1)
	snapshot2 := filepath.Join(baseDir, "snapshot2")
	snapshot3 := filepath.Join(baseDir, "snapshot3")

	if err := os.MkdirAll(snapshot2, 0755); err != nil {
		t.Fatalf("Failed to create snapshot2: %v", err)
	}
	if err := os.MkdirAll(snapshot3, 0755); err != nil {
		t.Fatalf("Failed to create snapshot3: %v", err)
	}

	// Create hardlinks in snapshot2 and snapshot3
	sharedPath := filepath.Join(snapshot1, "shared.txt")
	CreateHardlink(t, sharedPath, filepath.Join(snapshot2, "shared.txt"))
	CreateHardlink(t, sharedPath, filepath.Join(snapshot3, "shared.txt"))

	// Verify all three have the same inode
	inode1 := GetInode(t, sharedPath)
	inode2 := GetInode(t, filepath.Join(snapshot2, "shared.txt"))
	inode3 := GetInode(t, filepath.Join(snapshot3, "shared.txt"))

	if inode1 != inode2 || inode1 != inode3 {
		t.Errorf("All hardlinks should have same inode: %d, %d, %d", inode1, inode2, inode3)
	}

	// Run the scanner
	sc, err := NewSnapshotComparison([]string{snapshot1, snapshot2, snapshot3})
	if err != nil {
		t.Fatalf("NewSnapshotComparison failed: %v", err)
	}

	if err := sc.ScanSnapshots(); err != nil {
		t.Fatalf("ScanSnapshots failed: %v", err)
	}

	// Verify the file is in all three snapshots
	if fileInfo, ok := sc.InodeMap[inode1]; ok {
		snapCount := len(fileInfo.Snapshots)
		t.Logf("Inode %d appears in %d snapshots", inode1, snapCount)
		if snapCount != 3 {
			t.Errorf("Expected shared.txt to be in 3 snapshots, got %d", snapCount)
		}
	} else {
		t.Errorf("Inode %d not found in InodeMap", inode1)
	}

	// Check the RootEntry was built
	if sc.RootEntry == nil {
		t.Error("RootEntry is nil after scan")
	} else {
		t.Logf("RootEntry has %d children", len(sc.RootEntry.Children))
	}
}

// TestDirectoryStructures tests nested directories with hardlinks
func TestDirectoryStructures(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create snapshot1 with nested structure
	snapshot1 := CreateTestSnapshot(t, "snapshot1", map[string]string{
		"dir1/file.txt": "content in dir1",
		"dir2/file.txt": "content in dir2",
	})

	// Create snapshot2 directory
	baseDir := filepath.Dir(snapshot1)
	snapshot2 := filepath.Join(baseDir, "snapshot2")
	if err := os.MkdirAll(filepath.Join(snapshot2, "dir1"), 0755); err != nil {
		t.Fatalf("Failed to create snapshot2/dir1: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(snapshot2, "dir2"), 0755); err != nil {
		t.Fatalf("Failed to create snapshot2/dir2: %v", err)
	}

	// Create hardlink to dir1/file.txt
	CreateHardlink(t,
		filepath.Join(snapshot1, "dir1/file.txt"),
		filepath.Join(snapshot2, "dir1/file.txt"))

	// Create different file in dir2
	if err := os.WriteFile(
		filepath.Join(snapshot2, "dir2/file.txt"),
		[]byte("different content"),
		0644,
	); err != nil {
		t.Fatalf("Failed to create dir2/file.txt: %v", err)
	}

	// Get inodes
	inode1 := GetInode(t, filepath.Join(snapshot1, "dir1/file.txt"))
	inode2a := GetInode(t, filepath.Join(snapshot1, "dir2/file.txt"))
	inode2b := GetInode(t, filepath.Join(snapshot2, "dir2/file.txt"))

	t.Logf("dir1/file.txt inode: %d (should be shared)", inode1)
	t.Logf("snapshot1 dir2/file.txt inode: %d", inode2a)
	t.Logf("snapshot2 dir2/file.txt inode: %d", inode2b)

	if inode2a == inode2b {
		t.Error("dir2/file.txt should have different inodes in different snapshots")
	}

	// Run the scanner
	sc, err := NewSnapshotComparison([]string{snapshot1, snapshot2})
	if err != nil {
		t.Fatalf("NewSnapshotComparison failed: %v", err)
	}

	if err := sc.ScanSnapshots(); err != nil {
		t.Fatalf("ScanSnapshots failed: %v", err)
	}

	// Verify dir1/file.txt is shared
	if fileInfo, ok := sc.InodeMap[inode1]; ok {
		if len(fileInfo.Snapshots) != 2 {
			t.Errorf("Expected dir1/file.txt to be in 2 snapshots, got %d", len(fileInfo.Snapshots))
		}
	}

	// Verify dir2/file.txt files are counted separately
	if fileInfo, ok := sc.InodeMap[inode2a]; ok {
		if len(fileInfo.Snapshots) != 1 {
			t.Errorf("Expected snapshot1 dir2/file.txt to be in 1 snapshot, got %d", len(fileInfo.Snapshots))
		}
	}

	if fileInfo, ok := sc.InodeMap[inode2b]; ok {
		if len(fileInfo.Snapshots) != 1 {
			t.Errorf("Expected snapshot2 dir2/file.txt to be in 1 snapshot, got %d", len(fileInfo.Snapshots))
		}
	}
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

// ============================================================================
// Edge Case Tests
// ============================================================================

// TestEmptySnapshots tests handling of empty directories
func TestEmptySnapshots(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create an empty snapshot
	snapshot1 := CreateTestSnapshot(t, "snapshot1", map[string]string{})

	// Create snapshot2 with a file
	snapshot2 := CreateTestSnapshot(t, "snapshot2", map[string]string{
		"file.txt": "some content",
	})

	// Run the scanner
	sc, err := NewSnapshotComparison([]string{snapshot1, snapshot2})
	if err != nil {
		t.Fatalf("NewSnapshotComparison failed: %v", err)
	}

	if err := sc.ScanSnapshots(); err != nil {
		t.Fatalf("ScanSnapshots failed: %v", err)
	}

	// Should have exactly 1 inode
	if len(sc.InodeMap) != 1 {
		t.Errorf("Expected 1 inode in map, got %d", len(sc.InodeMap))
	}

	// Count total unique inodes (each represents at least one file)
	totalInodes := len(sc.InodeMap)

	t.Logf("Total unique inodes found: %d", totalInodes)
}

// TestSymlinkHandling tests behavior with symlinks
func TestSymlinkHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create snapshot with regular file
	snapshot1 := CreateTestSnapshot(t, "snapshot1", map[string]string{
		"file.txt": "regular file content",
	})

	// Create a symlink to the file
	filePath := filepath.Join(snapshot1, "file.txt")
	linkPath := filepath.Join(snapshot1, "link.txt")

	if err := os.Symlink(filePath, linkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Verify it's a symlink
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Failed to lstat link: %v", err)
	}

	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link.txt is not a symlink")
	}

	// Run the scanner
	sc, err := NewSnapshotComparison([]string{snapshot1})
	if err != nil {
		t.Fatalf("NewSnapshotComparison failed: %v", err)
	}

	if err := sc.ScanSnapshots(); err != nil {
		t.Fatalf("ScanSnapshots failed: %v", err)
	}

	// Count total unique inodes found
	totalInodes := len(sc.InodeMap)

	t.Logf("Found %d unique inodes with symlink present", totalInodes)

	// This test documents current behavior
	// The audit identified that filepath.Walk follows symlinks which could be problematic
	if totalInodes > 2 {
		t.Errorf("WARNING: Found more than 2 inodes (%d), symlink may be followed incorrectly", totalInodes)
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

// TestInvalidInputs tests various error conditions
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

// ============================================================================
// Size Calculation Tests
// ============================================================================

// TestUniqueSizeCalculation specifically tests unique size calculation
func TestUniqueSizeCalculation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create snapshot1 with 3 files
	snapshot1 := CreateTestSnapshot(t, "snapshot1", map[string]string{
		"unique1.txt": "content unique to snapshot1 (100 bytes)" + string(make([]byte, 60)),
		"unique2.txt": "another unique file in snapshot1 (100 bytes)" + string(make([]byte, 57)),
		"shared.txt":  "this file will be shared (100 bytes)" + string(make([]byte, 62)),
	})

	// Get file sizes
	info1, _ := os.Stat(filepath.Join(snapshot1, "unique1.txt"))
	info2, _ := os.Stat(filepath.Join(snapshot1, "unique2.txt"))
	infoShared, _ := os.Stat(filepath.Join(snapshot1, "shared.txt"))

	size1 := info1.Size()
	size2 := info2.Size()
	sizeShared := infoShared.Size()

	t.Logf("File sizes: unique1=%d, unique2=%d, shared=%d", size1, size2, sizeShared)

	// Create snapshot2
	baseDir := filepath.Dir(snapshot1)
	snapshot2 := filepath.Join(baseDir, "snapshot2")
	if err := os.MkdirAll(snapshot2, 0755); err != nil {
		t.Fatalf("Failed to create snapshot2: %v", err)
	}

	// Create hardlink to shared.txt
	CreateHardlink(t,
		filepath.Join(snapshot1, "shared.txt"),
		filepath.Join(snapshot2, "shared.txt"))

	// Create a unique file in snapshot2
	unique3Path := filepath.Join(snapshot2, "unique3.txt")
	if err := os.WriteFile(unique3Path, []byte("unique to snapshot2 (100 bytes)"+string(make([]byte, 64))), 0644); err != nil {
		t.Fatalf("Failed to create unique3.txt: %v", err)
	}

	info3, _ := os.Stat(unique3Path)
	size3 := info3.Size()
	t.Logf("File sizes: unique3=%d", size3)

	// Scan both snapshots
	sc, err := NewSnapshotComparison([]string{snapshot1, snapshot2})
	if err != nil {
		t.Fatalf("NewSnapshotComparison failed: %v", err)
	}

	if err := sc.ScanSnapshots(); err != nil {
		t.Fatalf("ScanSnapshots failed: %v", err)
	}

	// Expected totals
	expectedTotal := size1 + size2 + sizeShared + size3 // All files counted
	expectedUnique := size1 + size2 + size3             // shared.txt is NOT unique (appears in both snapshots)

	t.Logf("Root entry - Total: %d, Unique: %d", sc.RootEntry.Size, sc.RootEntry.UniqueSize)
	t.Logf("Expected    - Total: %d, Unique: %d", expectedTotal, expectedUnique)

	// Check total size
	if sc.RootEntry.Size != expectedTotal {
		t.Errorf("Total size incorrect: got %d, want %d", sc.RootEntry.Size, expectedTotal)
	}

	// Check unique size
	if sc.RootEntry.UniqueSize != expectedUnique {
		t.Errorf("Unique size incorrect: got %d, want %d", sc.RootEntry.UniqueSize, expectedUnique)
	}

	// Also check individual files
	t.Log("\nIndividual file analysis:")
	for name, child := range sc.RootEntry.Children {
		if !child.IsDir {
			t.Logf("  %s: Size=%d, UniqueSize=%d, Status=%d", name, child.Size, child.UniqueSize, child.Status)
		}
	}
}

// TestUniqueSizeWithDirectories tests unique size calculation with nested directories
func TestUniqueSizeWithDirectories(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create snapshot1 with nested structure
	snapshot1 := CreateTestSnapshot(t, "snapshot1", map[string]string{
		"dir1/file1.txt": "unique file in dir1 (50 bytes)" + string(make([]byte, 22)),
		"dir1/file2.txt": "shared file in dir1 (50 bytes)" + string(make([]byte, 21)),
		"dir2/file3.txt": "unique file in dir2 (50 bytes)" + string(make([]byte, 22)),
	})

	// Get sizes
	info1, _ := os.Stat(filepath.Join(snapshot1, "dir1/file1.txt"))
	info2, _ := os.Stat(filepath.Join(snapshot1, "dir1/file2.txt"))
	info3, _ := os.Stat(filepath.Join(snapshot1, "dir2/file3.txt"))

	size1 := info1.Size()
	size2 := info2.Size()
	size3 := info3.Size()

	// Create snapshot2
	baseDir := filepath.Dir(snapshot1)
	snapshot2 := filepath.Join(baseDir, "snapshot2")
	if err := os.MkdirAll(filepath.Join(snapshot2, "dir1"), 0755); err != nil {
		t.Fatalf("Failed to create snapshot2/dir1: %v", err)
	}

	// Hardlink file2.txt (shared)
	CreateHardlink(t,
		filepath.Join(snapshot1, "dir1/file2.txt"),
		filepath.Join(snapshot2, "dir1/file2.txt"))

	// Scan
	sc, err := NewSnapshotComparison([]string{snapshot1, snapshot2})
	if err != nil {
		t.Fatalf("NewSnapshotComparison failed: %v", err)
	}

	if err := sc.ScanSnapshots(); err != nil {
		t.Fatalf("ScanSnapshots failed: %v", err)
	}

	// Expected: file1 + file3 unique, file2 shared (counted once in total, zero in unique)
	expectedTotal := size1 + size2 + size3
	expectedUnique := size1 + size3 // file2 is shared

	t.Logf("Root - Total: %d, Unique: %d", sc.RootEntry.Size, sc.RootEntry.UniqueSize)
	t.Logf("Expected - Total: %d, Unique: %d", expectedTotal, expectedUnique)

	if sc.RootEntry.Size != expectedTotal {
		t.Errorf("Total size incorrect: got %d, want %d", sc.RootEntry.Size, expectedTotal)
	}

	if sc.RootEntry.UniqueSize != expectedUnique {
		t.Errorf("Unique size incorrect: got %d, want %d", sc.RootEntry.UniqueSize, expectedUnique)
	}

	// Check directory sizes
	dir1 := FindEntryByName(sc.RootEntry, "dir1")
	if dir1 != nil {
		t.Logf("dir1 - Total: %d, Unique: %d (should be %d + %d = %d total, %d unique)",
			dir1.Size, dir1.UniqueSize, size1, size2, size1+size2, size1)

		expectedDir1Total := size1 + size2
		expectedDir1Unique := size1 // only file1 is unique

		if dir1.Size != expectedDir1Total {
			t.Errorf("dir1 total size: got %d, want %d", dir1.Size, expectedDir1Total)
		}

		if dir1.UniqueSize != expectedDir1Unique {
			t.Errorf("dir1 unique size got %d, want %d", dir1.UniqueSize, expectedDir1Unique)
		}
	}
}
