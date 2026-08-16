package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestHeaderXSSGenericReflection(t *testing.T) {
	generic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var out strings.Builder
		out.WriteString("<html><table>")
		for k, vs := range r.Header {
			for _, v := range vs {
				fmt.Fprintf(&out, "<tr><td>%s</td><td>%s</td></tr>", k, v)
			}
		}
		out.WriteString("</table></html>")
		fmt.Fprint(w, out.String())
	}))
	defer generic.Close()

	cfg := &core.Config{}
	findings := ScanHeaderInjection(generic.Client(), cfg, core.CrawlResult{URL: generic.URL + "/p"})
	if len(findings) != 0 {
		t.Errorf("generic header reflection must not produce header-XSS findings, got %v", findings)
	}
}

func TestHeaderXSSRealSink(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			fmt.Fprintf(w, "<script>var x=%q;</script>", v)
			return
		}
		fmt.Fprint(w, "<html>ok</html>")
	}))
	defer real.Close()

	cfg := &core.Config{}
	findings := ScanHeaderInjection(real.Client(), cfg, core.CrawlResult{URL: real.URL + "/p"})
	ok := false
	for _, f := range findings {
		if strings.Contains(f.Type, "XSS via HTTP Header") && f.Parameter == "X-Forwarded-For" {
			ok = true
		}
	}
	if !ok {
		t.Errorf("expected header XSS finding on X-Forwarded-For, got %+v", findings)
	}
}
