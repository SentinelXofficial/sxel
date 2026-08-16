package integration

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/modules"
)

var (
	vulnappBase      string
	vulnappAvailable bool
	vulnappPhpCmd    *exec.Cmd
)

// TestMain builds & runs the PHP vulnapp (php -S) against a local MariaDB.
// If PHP or MariaDB is not available, vulnapp tests are skipped.
func TestMain(m *testing.M) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: repo root: %v\n", err)
		os.Exit(1)
	}

	phpBin, err := exec.LookPath("php")
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration: php not found — vulnapp tests will be skipped")
		code := m.Run()
		os.Exit(code)
	}

	if !mariadbReady() {
		fmt.Fprintln(os.Stderr, "integration: mariadb not reachable — vulnapp tests will be skipped")
		code := m.Run()
		os.Exit(code)
	}

	rootArgs, ok := mariadbRootArgs()
	if !ok {
		fmt.Fprintln(os.Stderr, "integration: no usable mariadb root credentials — vulnapp tests will be skipped")
		code := m.Run()
		os.Exit(code)
	}

	seedDB(rootArgs)

	pagesDir := filepath.Join(os.TempDir(), "vulnapp-pages")
	if err := os.MkdirAll(pagesDir, 0o755); err == nil {
		matches, _ := filepath.Glob(filepath.Join(repoRoot, "vulnapp", "src", "pages", "*"))
		for _, f := range matches {
			data, err := os.ReadFile(f)
			if err == nil {
				_ = os.WriteFile(filepath.Join(pagesDir, filepath.Base(f)), data, 0o644)
			}
		}
	}

	port := freePort()
	cmd := exec.Command(phpBin, "-S", "127.0.0.1:"+port, "-t", "public", "public/router.php")
	cmd.Dir = filepath.Join(repoRoot, "vulnapp")
	cmd.Env = append(os.Environ(), "PHP_CLI_SERVER_WORKERS=4")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "integration: start vulnapp php: %v\n", err)
		code := m.Run()
		os.Exit(code)
	}
	vulnappPhpCmd = cmd
	vulnappBase = "http://127.0.0.1:" + port

	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		resp, err := http.Get(vulnappBase + "/")
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		cmd.Process.Kill()
		fmt.Fprintln(os.Stderr, "integration: vulnapp php did not become ready")
		code := m.Run()
		os.Exit(code)
	}
	vulnappAvailable = true

	code := m.Run()
	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
	os.Exit(code)
}

func mariadbReady() bool {
	for _, bin := range []string{"mysqladmin", "mariadb-admin"} {
		if _, err := exec.LookPath(bin); err == nil {
			if out, err := exec.Command(bin, "ping").CombinedOutput(); err == nil || strings.Contains(string(out), "mysqld is alive") {
				return true
			}
		}
	}
	if out, err := exec.Command("service", "mariadb", "start").CombinedOutput(); err == nil {
		_ = out
		time.Sleep(2 * time.Second)
		for _, bin := range []string{"mysqladmin", "mariadb-admin"} {
			if out, err := exec.Command(bin, "ping").CombinedOutput(); err == nil || strings.Contains(string(out), "mysqld is alive") {
				return true
			}
		}
	}
	return false
}

func mariadbRootArgs() ([]string, bool) {
	candidates := [][]string{
		{"-u", "root"},
		{"-h", "127.0.0.1", "-u", "root", "-proot"},
		{"-h", "127.0.0.1", "-u", "root"},
	}
	for _, args := range candidates {
		if err := exec.Command("mysql", append(args, "-e", "SELECT 1")...).Run(); err == nil {
			return args, true
		}
	}
	return nil, false
}

func seedDB(rootArgs []string) {
	repoRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	for _, f := range []string{"schema.sql", "seed.sql"} {
		path := filepath.Join(repoRoot, "vulnapp", "db", f)
		cmd := exec.Command("mysql", append(rootArgs, path)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "integration: seed %s: %v\n%s\n", f, err, out)
		}
	}
	grant := `CREATE USER IF NOT EXISTS 'vulnapp'@'%' IDENTIFIED BY 'vulnapp';
CREATE USER IF NOT EXISTS 'vulnapp'@'127.0.0.1' IDENTIFIED BY 'vulnapp';
GRANT ALL PRIVILEGES ON vulnapp.* TO 'vulnapp'@'%';
GRANT ALL PRIVILEGES ON vulnapp.* TO 'vulnapp'@'127.0.0.1';
FLUSH PRIVILEGES;`
	if err := exec.Command("mysql", append(rootArgs, "-e", grant)...).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "integration: grant user: %v\n", err)
	}
}

func freePort() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "8899"
	}
	port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return port
}

func vulnTarget(path string) core.CrawlResult {
	return core.CrawlResult{URL: vulnappBase + path}
}

func vulnappHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

func requireVulnApp(t *testing.T) {
	t.Helper()
	if !vulnappAvailable {
		t.Skip("vulnapp skipped: php/mariadb not available")
	}
}

func TestVulnAppSQLiErrorBased(t *testing.T) {
	requireVulnApp(t)
	res := runScan(t, nil, modules.ScanSQLi, vulnTarget("/search?q=test"))
	assertHasType(t, res, "SQL Injection (Error-Based)")
}

func TestVulnAppSQLiUnion(t *testing.T) {
	requireVulnApp(t)
	res := runScan(t, nil, modules.ScanSQLi, vulnTarget("/search?q=1"))
	assertHasType(t, res, "SQL Injection Union-Based")
}

func TestVulnAppSQLiBooleanBlind(t *testing.T) {
	requireVulnApp(t)
	res := runScan(t, nil, modules.ScanBooleanBlindSQLi, vulnTarget("/product?id=1"))
	assertHasType(t, res, "SQL Injection Boolean-Based Blind")
}

func TestVulnAppSQLiTimeBlind(t *testing.T) {
	requireVulnApp(t)
	res := runScan(t, nil, modules.ScanBlindSQLiTime, vulnTarget("/product?id=1"))
	assertHasType(t, res, "SQL Injection Time-Based Blind")
}

func TestVulnAppXSSReflect(t *testing.T) {
	requireVulnApp(t)
	res := runScan(t, nil, modules.ScanXSS, vulnTarget("/search?q=hi"))
	assertHasType(t, res, "XSS")
}

func TestVulnAppCmdInjection(t *testing.T) {
	requireVulnApp(t)
	res := runScan(t, nil, modules.ScanCmdInjection, vulnTarget("/ping?host=127.0.0.1"))
	assertHasType(t, res, "Command Injection")
}

func TestVulnAppJWT(t *testing.T) {
	requireVulnApp(t)
	token := fetchJWToken(t)
	cfg := newCfg()
	cfg.Headers = map[string]string{"Authorization": "Bearer " + token}
	res := modules.ScanJWT(vulnappHTTPClient(), cfg, vulnTarget("/api/user"))
	assertHasType(t, res, "JWT Algorithm None")
}

func TestVulnAppPathTraversal(t *testing.T) {
	requireVulnApp(t)
	res := runScan(t, nil, modules.ScanPathTraversal, vulnTarget("/read?file=welcome.txt"))
	assertHasType(t, res, "Path Traversal")
}

func TestVulnAppOpenRedirect(t *testing.T) {
	requireVulnApp(t)
	res := runScan(t, nil, modules.ScanOpenRedirect, vulnTarget("/go?url=https://example.com"))
	assertHasType(t, res, "Open Redirect")
}

func fetchJWToken(t *testing.T) string {
	t.Helper()
	resp, err := http.Get(vulnappBase + "/api/token")
	if err != nil {
		t.Fatalf("fetch jwt: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	tok := strings.TrimSpace(string(b))
	if !strings.Contains(tok, ".") {
		t.Fatalf("unexpected jwt response: %q", b)
	}
	return tok
}
