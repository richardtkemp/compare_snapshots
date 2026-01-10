package main

import (
	"testing"
)

// TestFormatSize tests the size formatting function
func TestFormatSize(t *testing.T) {
	tests := []struct {
		name     string
		size     int64
		expected string
	}{
		{"zero bytes", 0, "0 B"},
		{"single byte", 1, "1 B"},
		{"bytes", 512, "512 B"},
		{"1023 bytes", 1023, "1023 B"},
		{"1 KiB", 1024, "1.0 KiB"},
		{"1.5 KiB", 1536, "1.5 KiB"},
		{"999 KiB", 1023 * 1024, "1023.0 KiB"},
		{"1 MiB", 1024 * 1024, "1.0 MiB"},
		{"1.5 MiB", 1536 * 1024, "1.5 MiB"},
		{"1 GiB", 1024 * 1024 * 1024, "1.0 GiB"},
		{"2.3 GiB", 2469606195, "2.3 GiB"}, // 2.3 * 1024^3
		{"1 TiB", 1024 * 1024 * 1024 * 1024, "1.0 TiB"},
		{"5.7 TiB", 6267218944614, "5.7 TiB"}, // 5.7 * 1024^4
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSize(tt.size)
			if result != tt.expected {
				t.Errorf("formatSize(%d) = %s, want %s", tt.size, result, tt.expected)
			}
		})
	}
}

// TestCalculateDirectorySizes tests recursive directory size calculation
func TestCalculateDirectorySizes(t *testing.T) {
	// Create a simple directory tree manually
	root := &DirectoryEntry{
		Name:     "root",
		IsDir:    true,
		Children: make(map[string]*DirectoryEntry),
	}

	// Add a file with size=1000
	file1 := &DirectoryEntry{
		Name:  "file1.txt",
		IsDir: false,
		Size:  1000,
		Inode: 100,
		SnapshotsInfo: map[string]bool{
			"snap1": true,
		},
	}

	// Add another file with size=2000
	file2 := &DirectoryEntry{
		Name:  "file2.txt",
		IsDir: false,
		Size:  2000,
		Inode: 200,
		SnapshotsInfo: map[string]bool{
			"snap1": true,
		},
	}

	// Add a subdirectory with its own file
	subdir := &DirectoryEntry{
		Name:     "subdir",
		IsDir:    true,
		Children: make(map[string]*DirectoryEntry),
	}

	file3 := &DirectoryEntry{
		Name:  "file3.txt",
		IsDir: false,
		Size:  500,
		Inode: 300,
		SnapshotsInfo: map[string]bool{
			"snap1": true,
			"snap2": true, // Shared file
		},
	}

	subdir.Children["file3.txt"] = file3
	root.Children["file1.txt"] = file1
	root.Children["file2.txt"] = file2
	root.Children["subdir"] = subdir

	// Create a comparison object with a proper InodeMap
	sc := &SnapshotComparison{
		InodeMap: map[uint64]*FileInfo{
			100: {Paths: map[string]string{"snap1": "file1.txt"}, Size: 1000, Inode: 100, Snapshots: map[string]bool{"snap1": true}},
			200: {Paths: map[string]string{"snap1": "file2.txt"}, Size: 2000, Inode: 200, Snapshots: map[string]bool{"snap1": true}},
			300: {Paths: map[string]string{"snap1": "file3.txt", "snap2": "file3.txt"}, Size: 500, Inode: 300, Snapshots: map[string]bool{"snap1": true, "snap2": true}},
		},
	}

	// Calculate sizes
	totalSize, uniqueSize := sc.calculateDirectorySizes(root)

	// Expected: 1000 + 2000 + 500 = 3500 total
	// Expected unique: 1000 (file1, snap1 only) + 2000 (file2, snap1 only) + 0 (file3, shared) = 3000
	// Note: I'm not 100% sure of the unique size logic, let's see what the test reveals

	expectedTotal := int64(3500)

	if totalSize != expectedTotal {
		t.Errorf("calculateDirectorySizes() totalSize = %d, want %d", totalSize, expectedTotal)
	}

	t.Logf("Total size: %d, Unique size: %d", totalSize, uniqueSize)

	// Let's not assert on unique size until we understand the logic
	// This test will help us understand how the code actually calculates it
}

// TestStatusToString tests status string conversion
func TestStatusToString(t *testing.T) {
	tests := []struct {
		name     string
		status   FileStatus
		expected string
	}{
		{"shared status", StatusShared, "Shared (same inode in multiple snapshots)"},
		{"different status", StatusDifferent, "Different (different inodes in snapshots)"},
		{"unique status", StatusUnique, "Unique (exists only in one snapshot)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusToString(tt.status)
			if result != tt.expected {
				t.Errorf("statusToString(%d) = %s, want %s", tt.status, result, tt.expected)
			}
		})
	}
}
