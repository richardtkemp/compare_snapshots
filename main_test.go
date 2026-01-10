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
