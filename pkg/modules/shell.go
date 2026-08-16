package modules

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

var webShellStrong = []string{
	"c99shell", "c99sh", "c100shell", "r57shell", "b374k",
	"phpspy", "indoxploit", "mini shell", "alfashell", "阿尔法",
	"wso2", "wso3", "wso4", "onefile", "safemode",
	"eval($_post", "eval($_request", "eval($_get",
	"assert($_post", "assert($_request",
	"base64_decode($_post", "base64_decode($_request",
	"system($_post", "passthru($_post", "shell_exec($_post",
	"exec($_post", "popen($_post", "proc_open($_post",
	"eval(gzinflate", "eval(base64_decode", "eval(str_rot13",
	"eval(request", "execute(request", "eval(chr(34)",
	"passthru($c", "system($c", "shell_exec($c",
	"#!shell", "webshell", "backdoor.php",
}

var webShellGeneric = []string{
	"<?php", "eval(", "gzinflate", "str_rot13", "base64_decode",
	"gzuncompress", "$_post", "$_request", "@$_", "chr(34)",
}

var webShellNamesTop = []string{
	"shell.php", "shell.asp", "shell.aspx", "shell.jsp",
	"c99.php", "c99shell.php", "c99shell.txt",
	"c100.php", "c100shell.php",
	"r57.php", "r57shell.php",
	"b374k.php", "b374k-shell.php",
	"wso.php", "wso2.php", "wso3.php", "wso4.php",
	"cmd.php", "cmd.asp", "cmd.aspx",
	"404.php", "eval.php", "eval-stdin.php",
	"webshell.php", "backdoor.php", "hacker.php",
	"alpha.php", "alfashell.php",
	"adminer.php", "phpinfo.php", "phpspy.php",
	"IndoXploit.php", "indoxploit.php",
}

var webShellNamesTail = []string{
	"c99.php.bak", "b374k.txt", "shell.php3", "cmd.jsp",
	"evaluator.php", "a.php", "p.php", "x.php", "z.php",
	"1.php", "2.php", "3.php", "phpinfo2.php",
	"index.php.bak", "config.php.bak", "test.php", "temp.php",
}

var webShellDirs = []string{
	"",
	"uploads/",
	"wp-content/uploads/",
	"images/",
	"tmp/",
	"media/",
}

var shellExecParams = []string{"cmd", "c", "command", "exec", "run", "p", "x", "q"}

const maxExecProbes = 15

var (
	shellOriginMu    sync.Mutex
	shellOriginsSeen = map[string]bool{}
)

func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func ScanWebShell(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	origin := originOf(target.URL)
	if origin == "" {
		return nil
	}
	shellOriginMu.Lock()
	if shellOriginsSeen[origin] {
		shellOriginMu.Unlock()
		return nil
	}
	shellOriginsSeen[origin] = true
	shellOriginMu.Unlock()

	var results []core.ScanResult
	base := origin

	probePaths := make([]string, 0, 250)
	for _, dir := range webShellDirs {
		for _, name := range webShellNamesTop {
			probePaths = append(probePaths, dir+name)
		}
	}
	for _, name := range webShellNamesTail {
		probePaths = append(probePaths, name)
	}

	type candidate struct {
		url    string
		body   string
		signal string
	}
	var cands []candidate

	seen := make(map[string]bool)
	for _, path := range probePaths {
		if seen[path] {
			continue
		}
		seen[path] = true
		probeURL := base + "/" + path

		req, err := http.NewRequest("GET", probeURL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(req, cfg)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body := core.ReadBody(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		low := strings.ToLower(body)
		if len(body) < 4 || !looksLikeScript(low) {
			continue
		}
		_, signal := matchWebShell(body)
		cands = append(cands, candidate{url: probeURL, body: body, signal: signal})
	}

	if len(cands) == 0 {
		return nil
	}

	confirmed := 0
	for _, c := range cands {
		if confirmed >= maxExecProbes {
			break
		}
		confirmed++
		if c.signal != "" && cfg.Verbose {
			output.Verbose("[webshell] %s matches %q — probing for command execution", c.url, c.signal)
		}
		vector, token := probeShellExec(client, cfg, c.url)
		if vector == "" {
			continue
		}
		results = append(results, core.ScanResult{
			Type:      "WebShell Confirmed (Remote Code Execution)",
			URL:       c.url,
			Method:    "GET/POST",
			Parameter: vector,
			Payload:   "echo " + token,
			Severity:  "CRITICAL",
			Evidence:  fmt.Sprintf("command output echoed (token %s) via %s — script executes commands", token, vector),
			Timestamp: time.Now(),
		})
		output.VulnInline("WEBSHELL", "CONFIRMED RCE %s (%s)", c.url, vector)
	}

	for _, c := range cands {
		if c.signal == "" {
			continue
		}
		sev := "CRITICAL"
		findingType := "WebShell Detected"
		if !webShellStrongContains(c.signal) {
			sev = "HIGH"
			findingType = "Possible WebShell (obfuscated eval)"
		}
		results = append(results, core.ScanResult{
			Type:      findingType,
			URL:       c.url,
			Method:    "GET",
			Parameter: "path",
			Payload:   c.url,
			Severity:  sev,
			Evidence:  fmt.Sprintf("HTTP 200 with webshell marker %q — command execution not confirmed", c.signal),
			Timestamp: time.Now(),
		})
	}

	return results
}

func looksLikeScript(low string) bool {
	if strings.Contains(low, "<?php") || strings.Contains(low, "<%") || strings.Contains(low, "<%@") {
		return true
	}
	if strings.Contains(low, "<html") || strings.Contains(low, "<body") || strings.Contains(low, "<pre") {
		return true
	}
	return len(low) > 8 && strings.Contains(low, "command")
}

func probeShellExec(client *http.Client, cfg *core.Config, shellURL string) (vector, token string) {
	token = "sxel" + randomHex(6)
	cmd := "echo " + token

	try := func(method, param, body string) bool {
		var req *http.Request
		var err error
		if method == "GET" {
			u, perr := core.SetParam(shellURL, param, cmd)
			if perr != nil {
				return false
			}
			req, err = http.NewRequest("GET", u, nil)
		} else {
			req, err = http.NewRequest("POST", shellURL, strings.NewReader(body))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}
		if err != nil {
			return false
		}
		core.ApplyHeaders(req, cfg)
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b := core.ReadBody(resp.Body)
		return strings.Contains(b, token)
	}

	for _, p := range shellExecParams {
		if try("GET", p, "") {
			return "GET " + p + "=echo <token>", token
		}
	}
	form := func(param string) string {
		return url.Values{param: []string{cmd}}.Encode()
	}
	for _, p := range shellExecParams {
		if try("POST", p, form(p)) {
			return "POST " + p + "=echo <token>", token
		}
	}
	if try("POST", "x", url.Values{"x": []string{`system("echo ` + token + `");`}}.Encode()) {
		return "POST x=system(...)", token
	}
	if try("POST", "cmd", url.Values{"cmd": []string{`system("echo ` + token + `");`}}.Encode()) {
		return "POST cmd=system(...)", token
	}
	return "", ""
}

func randomHex(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		fallback := fmt.Sprintf("%x", time.Now().UnixNano())
		if len(fallback) > n {
			fallback = fallback[:n]
		}
		return fallback
	}
	s := hex.EncodeToString(b)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func matchWebShell(body string) (bool, string) {
	low := strings.ToLower(body)

	for _, sig := range webShellStrong {
		if strings.Contains(low, sig) {
			return true, sig
		}
	}

	hits := 0
	for _, sig := range webShellGeneric {
		if strings.Contains(low, sig) {
			hits++
		}
	}
	if hits >= 3 && strings.Contains(low, "<?php") {
		return true, "obfuscated-eval (generic markers x" + fmt.Sprint(hits) + ")"
	}
	return false, ""
}

func webShellStrongContains(signal string) bool {
	for _, sig := range webShellStrong {
		if sig == signal {
			return true
		}
	}
	return false
}
