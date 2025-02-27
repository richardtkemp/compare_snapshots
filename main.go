package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// FileInfo represents information about a file
type FileInfo struct {
	Path      string
	Size      int64
	Inode     uint64
	Snapshots map[string]bool // which snapshots contain this file
}

// DirectoryEntry represents a directory or file in the tree
type DirectoryEntry struct {
	Name          string
	IsDir         bool
	Size          int64
	UniqueSize    int64
	Inode         uint64
	Children      map[string]*DirectoryEntry
	Status        FileStatus
	SnapshotsInfo map[string]bool // which snapshots contain this entry
}

// FileStatus represents the status of a file across snapshots
type FileStatus int

const (
	StatusShared    FileStatus = iota // Same inode in multiple snapshots
	StatusDifferent                    // Different inodes in different snapshots
	StatusUnique                       // Exists only in one snapshot
)

// SnapshotComparison holds the comparison data
type SnapshotComparison struct {
	InodeMap          map[uint64][]*FileInfo // Map of inodes to files
	Snapshots         []string               // List of snapshot names
	SnapshotRootPaths map[string]string      // Map of snapshot names to root paths
	RootEntry         *DirectoryEntry        // Root of the directory tree
	CurrentPath       []string               // Current navigation path
	ViewMode          ViewMode               // Current view mode
	App               *tview.Application     // tview application
	Tree              *tview.TreeView        // Tree view for navigation
	StatusBar         *tview.TextView        // Status bar
	InfoPanel         *tview.TextView        // Info panel
	SortMode          SortMode               // Current sort mode
}

// ViewMode represents different view modes
type ViewMode int

const (
	ViewTotal ViewMode = iota
	ViewUnique
)

// SortMode represents different sorting modes
type SortMode int

const (
	SortBySize SortMode = iota
	SortByName
	SortByUniqueness
)

// NewSnapshotComparison creates a new snapshot comparison
func NewSnapshotComparison(snapshots []string) (*SnapshotComparison, error) {
	if len(snapshots) < 1 {
		return nil, fmt.Errorf("at least one snapshot directory is required")
	}

	sc := &SnapshotComparison{
		InodeMap:          make(map[uint64][]*FileInfo),
		Snapshots:         make([]string, len(snapshots)),
		SnapshotRootPaths: make(map[string]string),
		RootEntry: &DirectoryEntry{
			Name:          "Root",
			IsDir:         true,
			Children:      make(map[string]*DirectoryEntry),
			SnapshotsInfo: make(map[string]bool),
		},
		ViewMode: ViewUnique,
		SortMode: SortBySize,
	}

	// Process snapshot paths
	for i, path := range snapshots {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path for %s: %v", path, err)
		}
		snapshotName := filepath.Base(absPath)
		sc.Snapshots[i] = snapshotName
		sc.SnapshotRootPaths[snapshotName] = absPath
	}

	return sc, nil
}

// ScanSnapshots scans all snapshots and builds the file index
func (sc *SnapshotComparison) ScanSnapshots() error {
	fmt.Println("Starting first pass: building inode map...")
	
	// First pass: scan all files and build inode map
	for _, snapshotName := range sc.Snapshots {
		rootPath := sc.SnapshotRootPaths[snapshotName]
		fmt.Printf("Scanning snapshot: %s at %s\n", snapshotName, rootPath)
		
		err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			
			// Skip directories in the inode map
			if info.IsDir() {
				return nil
			}
			
			// Get the inode number
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("failed to get system info for %s", path)
			}
			
			// Relativize the path to the snapshot root
			relPath, err := filepath.Rel(rootPath, path)
			if err != nil {
				return fmt.Errorf("failed to get relative path for %s: %v", path, err)
			}
			
			// Create or update file info in the inode map
			fileInfo := &FileInfo{
				Path:      relPath,
				Size:      info.Size(),
				Inode:     stat.Ino,
				Snapshots: map[string]bool{snapshotName: true},
			}
			
			// Add to inode map
			sc.InodeMap[stat.Ino] = append(sc.InodeMap[stat.Ino], fileInfo)
			
			return nil
		})
		
		if err != nil {
			return fmt.Errorf("failed to scan snapshot %s: %v", snapshotName, err)
		}
	}
	
	fmt.Printf("First pass complete. Found %d unique inodes.\n", len(sc.InodeMap))
	fmt.Println("Starting second pass: building directory tree...")
	
	// Second pass: build directory tree and calculate sizes
	for _, snapshotName := range sc.Snapshots {
		rootPath := sc.SnapshotRootPaths[snapshotName]
		fmt.Printf("Building tree for snapshot: %s\n", snapshotName)
		
		fileCount := 0
		dirCount := 0
		
		err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			
			// Relativize the path to the snapshot root
			relPath, err := filepath.Rel(rootPath, path)
			if err != nil {
				return fmt.Errorf("failed to get relative path for %s: %v", path, err)
			}
			
			// Skip root
			if relPath == "." {
				return nil
			}
			
			parts := strings.Split(relPath, string(filepath.Separator))
			currentEntry := sc.RootEntry
			
			// Navigate/create the path in our tree
			for i, part := range parts {
				isLast := i == len(parts)-1
				childEntry, exists := currentEntry.Children[part]
				
				if !exists {
					// Create new entry
					childEntry = &DirectoryEntry{
						Name:          part,
						IsDir:         info.IsDir() || !isLast,
						Children:      make(map[string]*DirectoryEntry),
						SnapshotsInfo: map[string]bool{snapshotName: true},
					}
					currentEntry.Children[part] = childEntry
					
					// Count new entries
					if childEntry.IsDir {
						dirCount++
					} else {
						fileCount++
					}
				} else {
					// Update existing entry
					childEntry.SnapshotsInfo[snapshotName] = true
				}
				
				// If it's a file, update size and status
				if isLast && !info.IsDir() {
					stat, ok := info.Sys().(*syscall.Stat_t)
					if !ok {
						return fmt.Errorf("failed to get system info for %s", path)
					}
					
					childEntry.Size = info.Size()
					childEntry.Inode = stat.Ino
					
					// Determine file status
					fileInfos := sc.InodeMap[stat.Ino]
					if len(fileInfos) > 1 {
						// If multiple files with same inode, check if they span snapshots
						snapshotCount := 0
						snapshotMap := make(map[string]bool)
						for _, fi := range fileInfos {
							for s := range fi.Snapshots {
								if !snapshotMap[s] {
									snapshotMap[s] = true
									snapshotCount++
								}
							}
						}
						
						if snapshotCount > 1 {
							childEntry.Status = StatusShared
							childEntry.UniqueSize = 0 // Shared files contribute 0 to unique size
						} else {
							childEntry.Status = StatusUnique
							childEntry.UniqueSize = info.Size()
						}
					} else {
						// Only one file with this inode
						childEntry.Status = StatusUnique
						childEntry.UniqueSize = info.Size()
					}
				}
				
				currentEntry = childEntry
			}
			
			return nil
		})
		
		if err != nil {
			return fmt.Errorf("failed to build directory tree for snapshot %s: %v", snapshotName, err)
		}
		
		fmt.Printf("Added %d files and %d directories from snapshot %s\n", fileCount, dirCount, snapshotName)
	}
	
	return sc.finishScanSnapshots()

	// This code is now in the finishScanSnapshots function
	return nil
}

// calculateDirectorySizes calculates total and unique sizes for directories
func (sc *SnapshotComparison) calculateDirectorySizes(entry *DirectoryEntry) (int64, int64) {
	if !entry.IsDir {
		return entry.Size, entry.UniqueSize
	}

	var totalSize, uniqueSize int64

	for _, child := range entry.Children {
		childTotal, childUnique := sc.calculateDirectorySizes(child)
		totalSize += childTotal
		uniqueSize += childUnique
	}

	entry.Size = totalSize
	entry.UniqueSize = uniqueSize
	return totalSize, uniqueSize
}

// Complete the ScanSnapshots function
func (sc *SnapshotComparison) finishScanSnapshots() error {
	// Calculate directory sizes recursively
	fmt.Println("Calculating directory sizes...")
	sc.calculateDirectorySizes(sc.RootEntry)

	// Determine directory status
	fmt.Println("Determining directory status...")
	sc.determineDirectoryStatus(sc.RootEntry)

	fmt.Println("Scan complete. Ready to display results.")
	return nil
}

// determineDirectoryStatus determines the status of directories
func (sc *SnapshotComparison) determineDirectoryStatus(entry *DirectoryEntry) {
	if !entry.IsDir {
		return
	}

	// Default to unique
	entry.Status = StatusUnique

	// Check if directory exists in multiple snapshots
	if len(entry.SnapshotsInfo) > 1 {
		entry.Status = StatusShared
	}

	// Process children
	for _, child := range entry.Children {
		sc.determineDirectoryStatus(child)
	}
}

// BuildTreeView builds the tree view for navigation
func (sc *SnapshotComparison) BuildTreeView() {
	// Keep the existing tree if it exists
	if sc.Tree == nil {
		sc.Tree = tview.NewTreeView()
	}
	
	// Create a root node for the current directory
	var rootText string
	if len(sc.CurrentPath) == 0 {
		rootText = "/"
	} else {
		rootText = sc.CurrentPath[len(sc.CurrentPath)-1] + "/"
	}
	
	root := tview.NewTreeNode(rootText)
	sc.Tree.SetRoot(root)
	
	// Get entries at current path
	currentEntry := sc.RootEntry
	for _, part := range sc.CurrentPath {
		if child, exists := currentEntry.Children[part]; exists {
			currentEntry = child
		} else {
			break
		}
	}
	
	// Add the current directory to the root reference (for info display)
	root.SetReference(currentEntry)
	
	// Add only the children of the current directory to the tree
	sc.addTreeNodes(root, currentEntry)
	
	// Set up keyboard handling
	sc.Tree.SetSelectedFunc(func(node *tview.TreeNode) {
		reference := node.GetReference()
		if reference == nil {
			return
		}
		
		nodeInfo := reference.(*DirectoryEntry)
		if nodeInfo.IsDir {
			// Navigate into directory
			if node.GetLevel() == 0 && len(sc.CurrentPath) > 0 {
				// Root level - go back up
				sc.CurrentPath = sc.CurrentPath[:len(sc.CurrentPath)-1]
			} else {
				sc.CurrentPath = append(sc.CurrentPath, nodeInfo.Name)
			}
			sc.RefreshUI()
		}
	})
	
	// Handle node expansion - load contents when a directory is expanded
	root.SetExpanded(true)  // Always expand the root node
}

// addTreeNodes adds directory entries as nodes to the tree
func (sc *SnapshotComparison) addTreeNodes(parent *tview.TreeNode, entry *DirectoryEntry) {
	// Clear existing children first
	parent.ClearChildren()
	
	// Sort children by the current sort mode
	var childNames []string
	for name := range entry.Children {
		childNames = append(childNames, name)
	}
	
	// Apply sorting
	switch sc.SortMode {
	case SortBySize:
		sort.Slice(childNames, func(i, j int) bool {
			if sc.ViewMode == ViewTotal {
				return entry.Children[childNames[i]].Size > entry.Children[childNames[j]].Size
			}
			return entry.Children[childNames[i]].UniqueSize > entry.Children[childNames[j]].UniqueSize
		})
	case SortByName:
		sort.Strings(childNames)
	case SortByUniqueness:
		sort.Slice(childNames, func(i, j int) bool {
			return entry.Children[childNames[i]].Status < entry.Children[childNames[j]].Status
		})
	}
	
	// Add children to tree
	for _, name := range childNames {
		child := entry.Children[name]
		var size int64
		if sc.ViewMode == ViewTotal {
			size = child.Size
		} else {
			size = child.UniqueSize
		}
		
		var nodeText string
		var snapCount = len(child.SnapshotsInfo)
		var statusText = statusToString(child.Status)
		
		if child.IsDir {
			nodeText = fmt.Sprintf("[%s] %s/ %s (%d snaps, %s)", 
				sc.getStatusColor(child), name, formatSize(size), snapCount, statusText)
		} else {
			nodeText = fmt.Sprintf("[%s] %s %s (%d snaps, %s)", 
				sc.getStatusColor(child), name, formatSize(size), snapCount, statusText)
		}
		
		childNode := tview.NewTreeNode(nodeText)
		childNode.SetReference(child)
		
		// For directories, set expanded state and add placeholder if it has children
		if child.IsDir && len(child.Children) > 0 {
			// Initialize as collapsed
			childNode.SetExpanded(false)
			
			// Add at least one placeholder child to show the expand arrow
			placeholder := tview.NewTreeNode("Loading...")
			childNode.AddChild(placeholder)
		}
		
		parent.AddChild(childNode)
	}
}

// expandDirectoryNode expands a directory node by adding its children
func (sc *SnapshotComparison) expandDirectoryNode(node *tview.TreeNode, entry *DirectoryEntry) {
	// Clear existing children (placeholder nodes)
	node.ClearChildren()
	
	// Sort children by the current sort mode
	var childNames []string
	for name := range entry.Children {
		childNames = append(childNames, name)
	}
	
	// Apply sorting
	switch sc.SortMode {
	case SortBySize:
		sort.Slice(childNames, func(i, j int) bool {
			if sc.ViewMode == ViewTotal {
				return entry.Children[childNames[i]].Size > entry.Children[childNames[j]].Size
			}
			return entry.Children[childNames[i]].UniqueSize > entry.Children[childNames[j]].UniqueSize
		})
	case SortByName:
		sort.Strings(childNames)
	case SortByUniqueness:
		sort.Slice(childNames, func(i, j int) bool {
			return entry.Children[childNames[i]].Status < entry.Children[childNames[j]].Status
		})
	}
	
	// Add all children to the expanded node
	for _, name := range childNames {
		child := entry.Children[name]
		var size int64
		if sc.ViewMode == ViewTotal {
			size = child.Size
		} else {
			size = child.UniqueSize
		}
		
		var nodeText string
		if child.IsDir {
			nodeText = fmt.Sprintf("[%s] %s/ %s", sc.getStatusColor(child), name, formatSize(size))
		} else {
			nodeText = fmt.Sprintf("[%s] %s %s", sc.getStatusColor(child), name, formatSize(size))
		}
		
		childNode := tview.NewTreeNode(nodeText)
		childNode.SetReference(child)
		
		// For directories, add a placeholder to indicate it has children
		if child.IsDir && len(child.Children) > 0 {
			childNode.SetExpanded(false)
			childNode.AddChild(tview.NewTreeNode("..."))
		}
		
		node.AddChild(childNode)
	}
}

// getStatusColor returns the color code for a file status
func (sc *SnapshotComparison) getStatusColor(entry *DirectoryEntry) string {
	switch entry.Status {
	case StatusShared:
		return "blue"
	case StatusDifferent:
		return "yellow"
	case StatusUnique:
		return "red"
	default:
		return "white"
	}
}

// UpdateInfoPanel updates the info panel with details about the selected entry
func (sc *SnapshotComparison) UpdateInfoPanel(entry *DirectoryEntry) {
	var info strings.Builder
	info.WriteString(fmt.Sprintf("Name: %s\n", entry.Name))
	info.WriteString(fmt.Sprintf("Type: %s\n", boolToFileType(entry.IsDir)))
	info.WriteString(fmt.Sprintf("Total Size: %s\n", formatSize(entry.Size)))
	info.WriteString(fmt.Sprintf("Unique Size: %s\n", formatSize(entry.UniqueSize)))
	
	if !entry.IsDir {
		info.WriteString(fmt.Sprintf("Inode: %d\n", entry.Inode))
	}
	
	info.WriteString("Present in snapshots: ")
	var snapshots []string
	for snapshot := range entry.SnapshotsInfo {
		snapshots = append(snapshots, snapshot)
	}
	sort.Strings(snapshots)
	info.WriteString(strings.Join(snapshots, ", "))
	info.WriteString("\n")
	
	info.WriteString(fmt.Sprintf("Status: %s\n", statusToString(entry.Status)))
	
	sc.InfoPanel.SetText(info.String())
}

// UpdateStatusBar updates the status bar with current navigation and view info
func (sc *SnapshotComparison) UpdateStatusBar() {
	var path strings.Builder
	path.WriteString("/")
	path.WriteString(strings.Join(sc.CurrentPath, "/"))
	
	var viewMode string
	if sc.ViewMode == ViewTotal {
		viewMode = "Total"
	} else {
		viewMode = "Unique"
	}
	
	var sortMode string
	switch sc.SortMode {
	case SortBySize:
		sortMode = "Size"
	case SortByName:
		sortMode = "Name"
	case SortByUniqueness:
		sortMode = "Uniqueness"
	}
	
	statusText := fmt.Sprintf("Path: %s | View: %s | Sort: %s | Toggle: t-view, s-sort | q-quit, u-up", 
		path.String(), viewMode, sortMode)
	
	sc.StatusBar.SetText(statusText)
}

// Initialize initializes the UI components
func (sc *SnapshotComparison) Initialize() {
	app := tview.NewApplication()
	
	// Create tree view
	tree := tview.NewTreeView()
	tree.SetBorder(true)
	tree.SetTitle("Directory Tree")
	// Using standard ASCII prefixes instead of unicode
	// and avoiding SetPrefixes and SetGraphics which might not be available
	
	// Create info panel
	infoPanel := tview.NewTextView()
	infoPanel.SetBorder(true)
	infoPanel.SetTitle("Info")
	infoPanel.SetDynamicColors(true)
	infoPanel.SetWordWrap(true)
	infoPanel.SetScrollable(true)
	
	// Create status bar
	statusBar := tview.NewTextView()
	statusBar.SetBorder(true)
	statusBar.SetTitle("Status")
	statusBar.SetDynamicColors(true)
	
	// Create a header with snapshot info
	headerText := tview.NewTextView()
	headerText.SetBorder(true)
	headerText.SetTitle("Snapshots")
	
	var header strings.Builder
	header.WriteString("Comparing ")
	header.WriteString(fmt.Sprintf("%d", len(sc.Snapshots)))
	header.WriteString(" snapshots: ")
	for i, snapshot := range sc.Snapshots {
		if i > 0 {
			header.WriteString(", ")
		}
		header.WriteString(snapshot)
	}
	header.WriteString("\n[blue]Blue[white]: Shared files (hardlinked) | [red]Red[white]: Unique files | [yellow]Yellow[white]: Different content")
	
	headerText.SetText(header.String())
	
	// Create layout
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(headerText, 4, 1, false).
		AddItem(tview.NewFlex().
			AddItem(tree, 0, 2, true).
			AddItem(infoPanel, 0, 1, false),
			0, 1, true).
		AddItem(statusBar, 3, 1, false)
	
	sc.App = app
	sc.Tree = tree
	sc.InfoPanel = infoPanel
	sc.StatusBar = statusBar
	
	// Set up input handling
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape, tcell.KeyRune:
			if event.Rune() == 'q' {
				app.Stop()
				return nil
			} else if event.Rune() == 't' {
				// Toggle view mode
				if sc.ViewMode == ViewTotal {
					sc.ViewMode = ViewUnique
				} else {
					sc.ViewMode = ViewTotal
				}
				sc.RefreshUI()
				return nil
			} else if event.Rune() == 's' {
				// Toggle sort mode
				sc.SortMode = (sc.SortMode + 1) % 3
				sc.RefreshUI()
				return nil
			} else if event.Rune() == 'u' {
				// Go up one level
				if len(sc.CurrentPath) > 0 {
					sc.CurrentPath = sc.CurrentPath[:len(sc.CurrentPath)-1]
					sc.RefreshUI()
				}
				return nil
			}
		}
		return event
	})
	
	// Build initial tree view
	sc.BuildTreeView()
	
	// Set up tree selection handler
	sc.Tree.SetChangedFunc(func(node *tview.TreeNode) {
		reference := node.GetReference()
		if reference != nil {
			sc.UpdateInfoPanel(reference.(*DirectoryEntry))
		}
	})
	
	// Since SetExpansionChangedFunc is not available, we'll use a different approach
	// We'll modify the BuildTreeView and addTreeNodes functions to handle expansion properly
	
	// Update status bar
	sc.UpdateStatusBar()
	
	// Set up main layout
	app.SetRoot(flex, true)
}

// RefreshUI refreshes the UI components
func (sc *SnapshotComparison) RefreshUI() {
	// If App is not initialized yet, just return
	if sc.App == nil {
		return
	}
	
	// Save the selected node if any
	var selectedNode *tview.TreeNode
	if sc.Tree != nil {
		selectedNode = sc.Tree.GetCurrentNode()
	}
	
	// Rebuild the tree view
	sc.BuildTreeView()
	sc.UpdateStatusBar()
	
	// Update info panel with current directory info
	currentEntry := sc.RootEntry
	for _, part := range sc.CurrentPath {
		if child, exists := currentEntry.Children[part]; exists {
			currentEntry = child
		} else {
			break
		}
	}
	sc.UpdateInfoPanel(currentEntry)
	
	// Try to restore selection
	if selectedNode != nil && selectedNode.GetReference() != nil {
		selectedEntry := selectedNode.GetReference().(*DirectoryEntry)
		if selectedEntry != nil {
			// Try to find the node with the same name in the new tree
			root := sc.Tree.GetRoot()
			if root != nil {
				for _, node := range root.GetChildren() {
					if node.GetReference() != nil {
						entry := node.GetReference().(*DirectoryEntry)
						if entry.Name == selectedEntry.Name {
							sc.Tree.SetCurrentNode(node)
							break
						}
					}
				}
			}
		}
	}
}

// Run starts the UI
func (sc *SnapshotComparison) Run() error {
	// Initialize UI components
	sc.Initialize()
	
	// Set up tree selection handler before starting the app
	if sc.Tree != nil {
		sc.Tree.SetChangedFunc(func(node *tview.TreeNode) {
			if node != nil && node.GetReference() != nil {
				entry := node.GetReference().(*DirectoryEntry)
				sc.UpdateInfoPanel(entry)
			}
		})
	}
	
	// Build the UI
	sc.BuildTreeView()
	sc.UpdateStatusBar()
	
	// Update info panel with root directory
	currentEntry := sc.RootEntry
	sc.UpdateInfoPanel(currentEntry)
	
	// Select the root node to start
	if sc.Tree != nil && sc.Tree.GetRoot() != nil {
		sc.Tree.SetCurrentNode(sc.Tree.GetRoot())
	}
	
	// Start the application
	return sc.App.Run()
}

// Helper functions

// formatSize formats a size in bytes to a human-readable string
func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

// boolToFileType converts a boolean to a file type string
func boolToFileType(isDir bool) string {
	if isDir {
		return "Directory"
	}
	return "File"
}

// statusToString converts a FileStatus to a string
func statusToString(status FileStatus) string {
	switch status {
	case StatusShared:
		return "Shared (same inode in multiple snapshots)"
	case StatusDifferent:
		return "Different (different inodes in snapshots)"
	case StatusUnique:
		return "Unique (exists only in one snapshot)"
	default:
		return "Unknown"
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: comparesnapshots <snapshot1> [snapshot2...]")
		os.Exit(1)
	}

	// Create a new snapshot comparison
	sc, err := NewSnapshotComparison(os.Args[1:])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Scan snapshots with progress indicator
	fmt.Println("Scanning snapshots...")
	
	// Start a goroutine for the progress indicator
	done := make(chan bool)
	go func() {
		indicators := []string{"|", "/", "-", "\\"}
		i := 0
		for {
			select {
			case <-done:
				return
			default:
				fmt.Printf("\rProcessing... %s", indicators[i])
				i = (i + 1) % len(indicators)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	
	// Do the scanning
	err = sc.ScanSnapshots()
	done <- true
	fmt.Println("\rScan completed!       ")
	
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	
	// Print some debug info before running the UI
	fmt.Printf("Scan completed!\n")
	fmt.Printf("Root directory has %d children\n", len(sc.RootEntry.Children))
	if len(sc.RootEntry.Children) > 0 {
		// Print first 5 child directories/files
		fmt.Println("First few directories/files:")
		count := 0
		for name, entry := range sc.RootEntry.Children {
			fmt.Printf("- %s (size: %s, unique: %s, status: %s)\n", 
				name, formatSize(entry.Size), formatSize(entry.UniqueSize), statusToString(entry.Status))
			count++
			if count >= 5 {
				break
			}
		}
	}

	// Run the UI
	err = sc.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
