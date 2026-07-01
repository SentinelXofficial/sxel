package core

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

const DefaultCheckpointFile = ".sxsc_checkpoint"

// CheckpointState holds the persistent scan state written to disk after every
// URL so a scan interrupted by Ctrl+C or a crash can be resumed with --resume.
type CheckpointState struct {
	mu          sync.Mutex
	file        string
	ScannedURLs map[string]bool `json:"scanned_urls"`
	Results     []ScanResult    `json:"results"`
}

// NewCheckpoint initialises a fresh checkpoint tracker that writes to file.
func NewCheckpoint(file string) *CheckpointState {
	if file == "" {
		file = DefaultCheckpointFile
	}
	return &CheckpointState{
		file:        file,
		ScannedURLs: map[string]bool{},
	}
}

// LoadCheckpoint reads an existing checkpoint from disk.
// Returns (state, true) on success, (nil, false) if the file does not exist.
func LoadCheckpoint(file string) (*CheckpointState, bool) {
	if file == "" {
		file = DefaultCheckpointFile
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, false
	}
	cs := &CheckpointState{file: file, ScannedURLs: map[string]bool{}}
	if err := json.Unmarshal(data, cs); err != nil {
		return nil, false
	}
	// Guard against JSON that contained "scanned_urls": null
	if cs.ScannedURLs == nil {
		cs.ScannedURLs = map[string]bool{}
	}
	fmt.Printf("[*] Checkpoint   : Resumed — %d URL(s) already scanned, %d result(s) reloaded from %s\n",
		len(cs.ScannedURLs), len(cs.Results), file)
	return cs, true
}

// IsScanned returns true if the URL has already been processed in a previous run.
func (c *CheckpointState) IsScanned(u string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ScannedURLs[u]
}

// MarkScanned records a URL as completed, appends its findings, and
// immediately flushes state to disk so the next Ctrl+C is safe.
func (c *CheckpointState) MarkScanned(u string, findings []ScanResult) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ScannedURLs == nil {
		c.ScannedURLs = map[string]bool{}
	}
	c.ScannedURLs[u] = true
	c.Results = append(c.Results, findings...)
	c.save()
}

// save serialises state to disk. Must be called under c.mu.
func (c *CheckpointState) save() {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(c.file, data, 0600)
}

// Delete removes the checkpoint file after a fully-completed scan so stale
// state does not confuse a later fresh run against the same target.
func (c *CheckpointState) Delete() {
	if c == nil {
		return
	}
	_ = os.Remove(c.file)
}
