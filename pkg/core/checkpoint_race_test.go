package core

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// Exercises the checkpoint under concurrent MarkScanned/IsScanned/Flush —
// Flush previously read dirty outside the mutex.
func TestCheckpointConcurrentFlushRace(t *testing.T) {
	dir := t.TempDir()
	cp := NewCheckpoint(filepath.Join(dir, "cp.json"))

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				u := fmt.Sprintf("http://t/%d/%d", n, j)
				cp.MarkScanned(u, []ScanResult{{Type: "x", URL: u}})
				_ = cp.IsScanned(u)
				if j%7 == 0 {
					cp.Flush()
				}
			}
		}(i)
	}
	wg.Wait()
	cp.Flush()

	if len(cp.ScannedURLs) != 16*50 {
		t.Fatalf("scanned = %d, want %d", len(cp.ScannedURLs), 16*50)
	}
	loaded, ok := LoadCheckpoint(cp.file)
	if !ok {
		t.Fatal("checkpoint file did not round-trip")
	}
	if len(loaded.ScannedURLs) != 16*50 {
		t.Fatalf("reloaded = %d, want %d", len(loaded.ScannedURLs), 16*50)
	}
}
