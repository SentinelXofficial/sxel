package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

func domContextJS(token string) string {
	t, _ := json.Marshal(token)
	return `(()=>{const token=` + string(t) + `;const w=document.createTreeWalker(document,NodeFilter.SHOW_ALL);let n;let ctx="";while(n=w.nextNode()){if(n.nodeType===3){if(n.nodeValue.indexOf(token)>=0){const p=n.parentElement;if(p&&/^script$/i.test(p.tagName)){return "script";}if(ctx!=="script"){ctx="text";}}}else if(n.nodeType===1){for(let i=0;i<n.attributes.length;i++){const a=n.attributes[i];if(a.value.indexOf(token)>=0){const nm=a.name.toLowerCase();if(nm.indexOf("on")===0||/^javascript:/i.test(a.value.trim())){return "event";}if(ctx!=="script"){ctx="attr";}}}}}return ctx;})()`
}

func probeDOMContext(bctx context.Context, pageURL, payload string) string {
	var out string
	err := chromedp.Run(bctx,
		chromedp.Navigate(pageURL),
		chromedp.Sleep(600*time.Millisecond),
		chromedp.Evaluate(domContextJS(payload), &out),
	)
	if err != nil {
		return ""
	}
	return out
}

func ScanDOMXSS(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	chrome := core.EnsureChrome()
	if chrome == "" {
		output.Info("[dom] headless browser unavailable — skipping DOM verification")
		return nil
	}
	payloads := []string{
		"<script>alert(document.domain)</script>",
		"\" autofocus onfocus=alert(1) x=\"",
		"';alert(1);//",
		"<img src=x onerror=alert(1)>",
	}
	actx, acancel := core.NewDOMAllocator(chrome)
	defer acancel()
	tctx, tcancel := context.WithTimeout(actx, 3*time.Minute)
	defer tcancel()
	bctx, bcancel := chromedp.NewContext(tctx)
	defer bcancel()
	chromedp.ListenTarget(bctx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			go func() {
				_ = chromedp.Run(bctx, page.HandleJavaScriptDialog(false))
			}()
		}
	})
	probe := func(rawURL, param string) {
		for _, payload := range payloads {
			u, err := core.SetParam(rawURL, param, payload)
			if err != nil {
				continue
			}
			ctx := probeDOMContext(bctx, u, payload)
			switch ctx {
			case "script", "event":
				results = append(results, core.ScanResult{
					Type: "DOM-verified XSS (" + ctx + " context)", URL: u,
					Method: "GET", Parameter: param, Payload: payload,
					Severity:  "HIGH",
					Evidence:  "payload reached an executable DOM context in a real browser",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [DOM-XSS] %s param=%s ctx=%s\n", u, param, ctx)
			case "text", "attr":
				results = append(results, core.ScanResult{
					Type: "Reflected XSS (non-executable DOM context)", URL: u,
					Method: "GET", Parameter: param, Payload: payload,
					Severity:  "LOW",
					Evidence:  "payload reflected into " + ctx + " node without script context",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [DOM-XSS] %s param=%s ctx=%s (inert)\n", u, param, ctx)
			}
		}
	}
	p, perr := url.Parse(target.URL)
	if perr != nil {
		return nil
	}
	params, _ := url.ParseQuery(p.RawQuery)
	for param := range params {
		probe(target.URL, param)
	}
	for _, form := range target.Forms {
		action := form.Action
		if action == "" {
			action = target.URL
		}
		for _, inp := range form.Inputs {
			probe(action, inp.Name)
		}
	}
	return results
}
