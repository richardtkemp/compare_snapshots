package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
