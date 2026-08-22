package modules

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Deep-recursion dirscan under -race: exercises the redirect re-enqueue path
// where overflow jobs are handed off to spawned goroutines when the jobs
// channel is full. Guards against WaitGroup accounting bugs (hangs, panics)
// and dropped recursive expansions. Note: the scanner client auto-follows the
// test server's redirects, so per-path request counts are NOT asserted here.
func TestDirScanRecursiveRace(t *testing.T) {
	wl := filepath.Join(t.TempDir(), "wl.txt")
	os.WriteFile(wl, []byte("admin\napi\nbackup\nconfig\ndev\nold\ntest\nv1\nv2\nweb"), 0o644)

	mu := sync.Mutex{}
	total := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		total++
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/sxel-dirscan-baseline") {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, r.URL.Path+"/x", http.StatusFound)
	}))
	defer srv.Close()

	cfg := testCfg()
	cfg.Threads = 2 // small worker pool → jobs channel fills → overflow spawn
	cfg.Wordlist = wl
	results := ScanDirsV2(srv.Client(), cfg, srv.URL, DirScanOpts{Depth: 3})

	if len(results) == 0 {
		t.Fatal("expected findings from recursive scan")
	}
	if total < 50 {
		t.Fatalf("suspiciously few requests (%d) — recursive expansion likely dropped jobs", total)
	}
}
