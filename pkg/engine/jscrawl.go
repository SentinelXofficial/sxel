package engine

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

func (c *Crawler) jsRender(pageURL string) ([]string, []core.Form) {
	chrome := core.EnsureChrome()
	if chrome == "" {
		return nil, nil
	}
	actx, acancel := core.NewDOMAllocator(chrome)
	defer acancel()
	tctx, tcancel := context.WithTimeout(actx, 30*time.Second)
	defer tcancel()
	bctx, bcancel := chromedp.NewContext(tctx)
	defer bcancel()

	var networkURLs []string
	var nuMu sync.Mutex
	chromedp.ListenTarget(bctx, func(ev interface{}) {
		if req, ok := ev.(*network.EventRequestWillBeSent); ok {
			if strings.HasPrefix(req.Request.URL, "http://") || strings.HasPrefix(req.Request.URL, "https://") {
				nuMu.Lock()
				networkURLs = append(networkURLs, req.Request.URL)
				nuMu.Unlock()
			}
		}
	})

	var dom string
	err := chromedp.Run(bctx,
		chromedp.Navigate(pageURL),
		// Wait for document load before sampling the DOM — a blind fixed
		// sleep raced page rendering under load and made JS-discovery flaky.
		chromedp.Poll(`document.readyState === "complete"`, nil, chromedp.WithPollingTimeout(15*time.Second)),
		chromedp.Sleep(1500*time.Millisecond),
		chromedp.OuterHTML("html", &dom, chromedp.ByQuery),
	)
	if err != nil {
		return nil, nil
	}
	links := c.extractLinks(dom, pageURL)
	nuMu.Lock()
	for _, u := range networkURLs {
		if !c.IsInScope(u) {
			continue
		}
		ru, perr := url.Parse(u)
		if perr != nil || isStaticAsset(ru) {
			continue
		}
		links = append(links, u)
	}
	nuMu.Unlock()
	forms := ExtractForms(dom, pageURL)
	if c.cfg.Verbose {
		output.Verbose("[crawl-js] %s -> %d link(s), %d form(s)", pageURL, len(links), len(forms))
	}
	return links, forms
}
