package engine

import (
	"github.com/SentinelXofficial/sxel/pkg/core"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

type Crawler struct {
	client   *http.Client
	cfg      *core.Config
	visited  map[string]bool
	mu       sync.Mutex
	baseHost string
	OnPage   func(core.CrawlResult, int) // streaming callback
}

func NewCrawler(client *http.Client, cfg *core.Config) *Crawler {
	return &Crawler{
		client:  client,
		cfg:     cfg,
		visited: make(map[string]bool),
	}
}

// Crawl performs BFS crawling up to maxDepth, returns all found pages+forms.
// Uses a ring-buffer queue (head index) to avoid the GC-unfriendly queue[1:]
// pattern that leaks memory on large crawls.
func (c *Crawler) Crawl(startURL string, maxDepth int) []core.CrawlResult {
	if p, err := url.Parse(startURL); err == nil {
		c.baseHost = p.Host
	}

	type qitem struct {
		u     string
		depth int
	}
	var results []core.CrawlResult
	queue := []qitem{{u: startURL, depth: 0}}
	head := 0

	si := 0
	lastPrint := time.Now()

	for head < len(queue) {
		if c.cfg.MaxPages > 0 && len(results) >= c.cfg.MaxPages {
			if c.cfg.Verbose {
				fmt.Printf("  \033[90m[crawl] --max-pages limit (%d) reached\033[0m\n", c.cfg.MaxPages)
			}
			break
		}
		item := queue[head]
		head++

		c.mu.Lock()
		if c.visited[item.u] {
			c.mu.Unlock()
			continue
		}
		c.visited[item.u] = true
		c.mu.Unlock()

		if c.cfg.Exclude != "" && strings.Contains(item.u, c.cfg.Exclude) {
			continue
		}
		if c.cfg.Verbose {
			fmt.Printf("  \033[90m[crawl] depth=%d %s\033[0m\n", item.depth, item.u)
		}

		// Real-time progress tick (every 80ms to avoid flooding terminal)
		if time.Since(lastPrint) > 80*time.Millisecond {
			fmt.Printf("\r\033[K[*] crawl: %d pages, %d queued", len(results), len(queue)-head)
			si++
			lastPrint = time.Now()
		}

		links, forms, err := c.fetchPage(item.u)
		if err != nil {
			if c.cfg.Verbose {
				fmt.Printf("  \033[90m[crawl-err] %v\033[0m\n", err)
			}
			continue
		}
		cr := core.CrawlResult{URL: item.u, Forms: forms}
		results = append(results, cr)
		if c.OnPage != nil {
			c.OnPage(cr, len(results))
		}

		if item.depth < maxDepth {
			for _, lnk := range links {
				c.mu.Lock()
				seen := c.visited[lnk]
				c.mu.Unlock()
				if !seen {
					queue = append(queue, qitem{u: lnk, depth: item.depth + 1})
				}
			}
		}

		// Periodic compaction: when head grows past 1000 discarded entries,
		// compact the queue to let the GC reclaim the dequeued items.
		if head > 1000 {
			queue = queue[head:]
			head = 0
		}
	}
	fmt.Printf("\r\033[K[+] Crawled %d page(s), %d form(s)\n", len(results), countForms(results))
	return results
}

func (c *Crawler) fetchPage(pageURL string) ([]string, []core.Form, error) {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return nil, nil, err
	}
	core.ApplyHeaders(req, c.cfg)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	bs := core.ReadBody(resp.Body)
	return c.extractLinks(bs, pageURL), ExtractForms(bs, pageURL), nil
}

func (c *Crawler) extractLinks(body, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	var links []string
	seen := map[string]bool{}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" {
					if r := ResolveURL(base, a.Val); r != "" && c.IsInScope(r) && !seen[r] {
						seen[r] = true
						links = append(links, r)
					}
				}
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	return links
}

// ExtractForms parses all <form> elements with their inputs
func ExtractForms(body, baseURL string) []core.Form {
	var forms []core.Form
	base, _ := url.Parse(baseURL)

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return forms
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			f := core.Form{Action: baseURL, Method: "GET"}
			for _, a := range n.Attr {
				switch a.Key {
				case "action":
					if a.Val != "" {
						if r := ResolveURL(base, a.Val); r != "" {
							f.Action = r
						}
					}
				case "method":
					f.Method = strings.ToUpper(a.Val)
				}
			}

			var gather func(*html.Node)
			gather = func(ch *html.Node) {
				if ch.Type == html.ElementNode {
					switch ch.Data {
					case "input", "textarea", "select":
						inp := core.Input{Type: "text", Value: "fuzz"}
						for _, a := range ch.Attr {
							switch a.Key {
							case "name":
								inp.Name = a.Val
							case "type":
								inp.Type = strings.ToLower(a.Val)
							case "value":
								inp.Value = a.Val
							}
						}
						skip := inp.Name == "" ||
							inp.Type == "submit" || inp.Type == "reset" ||
							inp.Type == "button" || inp.Type == "image"
						if !skip {
							f.Inputs = append(f.Inputs, inp)
						}
					}
				}
				for c := ch.FirstChild; c != nil; c = c.NextSibling {
					gather(c)
				}
			}
			gather(n)

			if len(f.Inputs) > 0 {
				forms = append(forms, f)
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	return forms
}

// FetchForms fetches a single page and returns its forms
func FetchForms(client *http.Client, cfg *core.Config, pageURL string) ([]core.Form, error) {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return nil, err
	}
	core.ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bs := core.ReadBody(resp.Body)
	return ExtractForms(bs, pageURL), nil
}

func ResolveURL(base *url.URL, href string) string {
	if href == "" ||
		strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "tel:") {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// isInScope returns true if link should be crawled.
// Logic:
//  1. Explicit --out-of-scope patterns are checked first and win.
//  2. If --scope patterns are set, link must match at least one.
//  3. Fall back to same-host check when no scope patterns given.
func (c *Crawler) IsInScope(link string) bool {
	p, err := url.Parse(link)
	if err != nil {
		return false
	}
	host := p.Host

	// --- out-of-scope wins unconditionally ---
	for _, pat := range c.cfg.OutOfScope {
		if MatchScope(pat, host, link) {
			return false
		}
	}

	// --- explicit scope must match ---
	if len(c.cfg.Scope) > 0 {
		for _, pat := range c.cfg.Scope {
			if MatchScope(pat, host, link) {
				return true
			}
		}
		return false
	}

	// --- default: same host ---
	return host == c.baseHost
}

// matchScope tests host / fullURL against a pattern.
// Patterns supported:
//   - "*.example.com"      → any subdomain of example.com
//   - "example.com"        → exact host match
//   - "http://example.com/api*" → URL prefix match (trailing * stripped)
func MatchScope(pattern, host, fullURL string) bool {
	pat := strings.TrimSpace(pattern)
	if pat == "" {
		return false
	}
	// URL prefix pattern (contains "://")
	if strings.Contains(pat, "://") {
		prefix := strings.TrimSuffix(pat, "*")
		return strings.HasPrefix(fullURL, prefix)
	}
	// Wildcard subdomain: *.example.com
	if strings.HasPrefix(pat, "*.") {
		suffix := pat[1:] // ".example.com"
		return strings.HasSuffix(host, suffix)
	}
	// Exact host match
	return host == pat
}


func countForms(results []core.CrawlResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Forms)
	}
	return n
}
