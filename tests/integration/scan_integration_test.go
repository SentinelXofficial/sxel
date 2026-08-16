package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/modules"
)

func TestIntegrationSQLi(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(sqliVulnHandler))
	defer vuln.Close()
	res := runScan(t, vuln, modules.ScanSQLi, core.CrawlResult{URL: vuln.URL + "/?id=1"})
	assertHasType(t, res, "SQL Injection (Error-Based)")

	safe := httptest.NewServer(http.HandlerFunc(sqliSafeHandler))
	defer safe.Close()
	res = runScan(t, safe, modules.ScanSQLi, core.CrawlResult{URL: safe.URL + "/?id=1"})
	assertClean(t, res)
}

func TestIntegrationXSS(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"text-node", xssVulnTextHandler},
		{"script-block", xssVulnScriptHandler},
		{"attribute", xssVulnAttrHandler},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vuln := httptest.NewServer(tc.handler)
			defer vuln.Close()
			res := runScan(t, vuln, modules.ScanXSS, core.CrawlResult{URL: vuln.URL + "/?q=hi"})
			assertHasType(t, res, "XSS")
		})
	}

	t.Run("safe", func(t *testing.T) {
		safe := httptest.NewServer(http.HandlerFunc(xssSafeHandler))
		defer safe.Close()
		res := runScan(t, safe, modules.ScanXSS, core.CrawlResult{URL: safe.URL + "/?q=hi"})
		assertClean(t, res)
	})
}

func TestIntegrationSSRF(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(ssrfVulnHandler))
	defer vuln.Close()
	res := runScan(t, vuln, modules.ScanSSRF, core.CrawlResult{URL: vuln.URL + "/?url=http://example.com"})
	assertHasType(t, res, "SSRF")

	safe := httptest.NewServer(http.HandlerFunc(ssrfSafeHandler))
	defer safe.Close()
	res = runScan(t, safe, modules.ScanSSRF, core.CrawlResult{URL: safe.URL + "/?url=http://example.com"})
	assertClean(t, res)
}

func TestIntegrationJWTHeader(t *testing.T) {
	vuln := httptest.NewServer(jwtAuthHandler("secret", true))
	defer vuln.Close()
	tok := buildTestJWT("secret")
	cfg := newCfg()
	cfg.Headers = map[string]string{"Authorization": "Bearer " + tok}
	res := modules.ScanJWT(vuln.Client(), cfg, core.CrawlResult{URL: vuln.URL + "/"})
	assertHasType(t, res, "JWT")

	safe := httptest.NewServer(jwtAuthHandler("V3ry-Str0ng-R4nd0m-K3y-981274", false))
	defer safe.Close()
	cfg = newCfg()
	cfg.Headers = map[string]string{"Authorization": "Bearer " + buildTestJWT("V3ry-Str0ng-R4nd0m-K3y-981274")}
	res = modules.ScanJWT(safe.Client(), cfg, core.CrawlResult{URL: safe.URL + "/"})
	assertClean(t, res)
}

func TestIntegrationJWTCookie(t *testing.T) {
	vuln := httptest.NewServer(jwtAuthHandler("secret", true))
	defer vuln.Close()
	tok := buildTestJWT("secret")
	cfg := newCfg()
	cfg.Cookie = "session=" + tok
	res := modules.ScanJWT(vuln.Client(), cfg, core.CrawlResult{URL: vuln.URL + "/"})
	assertHasType(t, res, "JWT")
}

func TestIntegrationGraphQL(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(gqlVulnHandler))
	defer vuln.Close()
	cfg := newCfg()
	res := modules.ScanGraphQL(vuln.Client(), cfg, vuln.URL+"/graphql")
	assertHasType(t, res, "GraphQL")

	safe := httptest.NewServer(http.HandlerFunc(gqlSafeHandler))
	defer safe.Close()
	cfg = newCfg()
	res = modules.ScanGraphQL(safe.Client(), cfg, safe.URL+"/graphql")
	assertClean(t, res)
}

func TestIntegrationCmdInjection(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(cmdiVulnHandler))
	defer vuln.Close()
	res := runScan(t, vuln, modules.ScanCmdInjection, core.CrawlResult{URL: vuln.URL + "/?cmd=x"})
	assertHasType(t, res, "Command Injection")

	form := core.CrawlResult{
		URL: vuln.URL + "/?cmd=x",
		Forms: []core.Form{{
			Action: vuln.URL + "/form",
			Method: "GET",
			Inputs: []core.Input{{Name: "cmd", Type: "text", Value: "x"}},
		}},
	}
	res = runScan(t, vuln, modules.ScanCmdInjection, form)
	assertHasType(t, res, "via core.Form")

	safe := httptest.NewServer(http.HandlerFunc(cmdiSafeHandler))
	defer safe.Close()
	res = runScan(t, safe, modules.ScanCmdInjection, core.CrawlResult{URL: safe.URL + "/?cmd=x"})
	assertClean(t, res)
}

func TestIntegrationNoSQLi(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(nosqlVulnHandler))
	defer vuln.Close()
	res := runScan(t, vuln, modules.ScanNoSQLi, core.CrawlResult{URL: vuln.URL + "/?id=1"})
	assertHasType(t, res, "NoSQL Injection")

	safe := httptest.NewServer(http.HandlerFunc(nosqlSafeHandler))
	defer safe.Close()
	res = runScan(t, safe, modules.ScanNoSQLi, core.CrawlResult{URL: safe.URL + "/?id=1"})
	assertClean(t, res)
}
