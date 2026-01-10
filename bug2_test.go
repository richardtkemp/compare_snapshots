package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestUniqueSizeCalculation specifically tests Bug #2 - unique size calculation
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

	// Check unique size - THIS IS BUG #2
	if sc.RootEntry.UniqueSize != expectedUnique {
		t.Errorf("BUG #2: Unique size incorrect: got %d, want %d", sc.RootEntry.UniqueSize, expectedUnique)
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
		t.Errorf("BUG #2: Unique size incorrect: got %d, want %d", sc.RootEntry.UniqueSize, expectedUnique)
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
			t.Errorf("BUG #2 in dir1: unique size got %d, want %d", dir1.UniqueSize, expectedDir1Unique)
		}
	}
}
