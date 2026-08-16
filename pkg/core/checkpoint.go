package core

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
)

const DefaultCheckpointFile = ".sxel_checkpoint"

type CheckpointState struct {
	mu          sync.Mutex
	file        string
	ScannedURLs map[string]bool `json:"scanned_urls"`
	Results     []ScanResult    `json:"results"`
	dirty       bool
	lastSave    time.Time
}

func NewCheckpoint(file string) *CheckpointState {
	if file == "" {
		file = DefaultCheckpointFile
	}
	return &CheckpointState{
		file:        file,
		ScannedURLs: map[string]bool{},
	}
}

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
	if cs.ScannedURLs == nil {
		cs.ScannedURLs = map[string]bool{}
	}
	output.Info("Checkpoint: Resumed — %d URL(s) already scanned, %d result(s) reloaded from %s",
		len(cs.ScannedURLs), len(cs.Results), file)
	return cs, true
}

func (c *CheckpointState) IsScanned(u string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ScannedURLs[u]
}

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
	c.dirty = true
	if time.Since(c.lastSave) > 5*time.Second {
		c.saveLocked()
	}
}

func (c *CheckpointState) Flush() {
	if c == nil || !c.dirty {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.saveLocked()
}

func (c *CheckpointState) saveLocked() {
	if !c.dirty {
		return
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	tmp := c.file + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		output.Warn("checkpoint: cannot write %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, c.file); err != nil {
		output.Warn("checkpoint: cannot rename %s → %s: %v", tmp, c.file, err)
		return
	}
	c.dirty = false
	c.lastSave = time.Now()
}

func (c *CheckpointState) Delete() {
	if c == nil {
		return
	}
	_ = os.Remove(c.file)
}
