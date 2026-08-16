package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("writing tar header for %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("writing tar content for %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}
	return buf.Bytes()
}

func TestBuildFromSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testTarGz(t, map[string]string{
			"fake-1.0.0/go.mod":        "module example.com/fake\n\ngo 1.21\n",
			"fake-1.0.0/main.go":       "package main\n\nfunc main() {}\n",
			"fake-1.0.0/internal/x.go": "package internal\n",
		}))
	}))
	defer server.Close()

	old := sourceClient
	sourceClient = &http.Client{Timeout: 5 * time.Second}
	defer func() { sourceClient = old }()

	resp, err := sourceClient.Get(server.URL + "/tar.gz")
	if err != nil {
		t.Fatalf("GET tarball: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET tarball: HTTP %d", resp.StatusCode)
	}

	dest := t.TempDir()
	if err := extractSourceTarball(resp.Body, dest); err != nil {
		t.Fatalf("extractSourceTarball: %v", err)
	}

	for _, want := range []string{"go.mod", "main.go", "internal/x.go"} {
		if _, err := os.Stat(filepath.Join(dest, filepath.FromSlash(want))); err != nil {
			t.Errorf("missing extracted file %s: %v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "fake-1.0.0")); !os.IsNotExist(err) {
		t.Error("top-level directory component was not stripped")
	}

	modData, err := os.ReadFile(filepath.Join(dest, "go.mod"))
	if err != nil {
		t.Fatalf("reading extracted go.mod: %v", err)
	}
	if !strings.Contains(string(modData), "module example.com/fake") {
		t.Errorf("go.mod content mismatch: %q", string(modData))
	}
}

func TestBuildFromSourceErrors(t *testing.T) {
	t.Run("invalid tar.gz", func(t *testing.T) {
		if err := extractSourceTarball(bytes.NewReader([]byte("this is not a tarball")), t.TempDir()); err == nil {
			t.Error("expected error for invalid tar.gz data, got nil")
		}
	})

	t.Run("missing go.mod", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(testTarGz(t, map[string]string{
				"fake-1.0.0/main.go": "package main\n",
			}))
		}))
		defer server.Close()

		old := sourceClient
		sourceClient = &http.Client{Timeout: 5 * time.Second}
		defer func() { sourceClient = old }()

		dest := t.TempDir()
		resp, err := sourceClient.Get(server.URL + "/tar.gz")
		if err != nil {
			t.Fatalf("GET tarball: %v", err)
		}
		defer resp.Body.Close()
		if err := extractSourceTarball(resp.Body, dest); err != nil {
			t.Fatalf("extractSourceTarball: %v", err)
		}
		if err := checkSourceTree(dest); err == nil {
			t.Error("expected error for missing go.mod, got nil")
		}
	})

	t.Run("wrong module path", func(t *testing.T) {
		dest := t.TempDir()
		if err := os.WriteFile(filepath.Join(dest, "go.mod"), []byte("module example.com/other\n\ngo 1.21\n"), 0o644); err != nil {
			t.Fatalf("writing go.mod: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(dest, "cmd", "sxel"), 0o755); err != nil {
			t.Fatalf("mkdir cmd/sxel: %v", err)
		}
		if err := checkSourceTree(dest); err == nil {
			t.Error("expected error for wrong module path, got nil")
		}
	})

	t.Run("tarball 404", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		defer server.Close()

		old := sourceClient
		sourceClient = &http.Client{Timeout: 5 * time.Second}
		defer func() { sourceClient = old }()

		if err := buildFromSource("v9.9.9", filepath.Join(t.TempDir(), "out")); err == nil {
			t.Error("expected error for 404 tarball, got nil")
		} else if !strings.Contains(err.Error(), "HTTP 404") {
			t.Errorf("expected HTTP 404 in error, got: %v", err)
		}
	})
}

func TestUpdateFallsBackToSource(t *testing.T) {
	cases := []struct {
		name       string
		respStatus int
		want       bool
	}{
		{"http 404", 404, true},
		{"http 500", 500, false},
		{"http 200", 200, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFallbackError(tc.respStatus); got != tc.want {
				t.Errorf("isFallbackError(%d) = %v, want %v", tc.respStatus, got, tc.want)
			}
		})
	}
}
