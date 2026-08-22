package engine

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

type Crawler struct {
	client   *http.Client
	cfg      *core.Config
	visited  map[string]bool
	sigSeen  map[string]int
	baseHost string
	OnPage   func(core.CrawlResult, int)
}

const maxQueryVariantsPerPath = 10

func NewCrawler(client *http.Client, cfg *core.Config) *Crawler {
	return &Crawler{
		client:  client,
		cfg:     cfg,
		visited: make(map[string]bool),
		sigSeen: make(map[string]int),
	}
}

func pageSignature(u *url.URL) string {
	names := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	return u.Scheme + "://" + u.Host + u.Path + "?" + strings.Join(names, "&")
}

func (c *Crawler) sigAdd(u *url.URL) bool {
	sig := pageSignature(u)
	limit := c.cfg.MaxQueryVariants
	if limit <= 0 {
		limit = maxQueryVariantsPerPath
	}
	if c.sigSeen[sig] >= limit {
		return false
	}
	c.sigSeen[sig]++
	return true
}

var staticAssetExts = map[string]bool{
	".css": true, ".js": true, ".mjs": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".webp": true, ".bmp": true, ".tif": true, ".tiff": true,
	".pdf": true, ".zip": true, ".gz": true, ".tar": true, ".7z": true, ".rar": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".wav": true,
	".ogg": true, ".webm": true, ".flv": true, ".swf": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".exe": true, ".dll": true, ".bin": true, ".iso": true, ".psd": true, ".ai": true,
}

func isStaticAsset(u *url.URL) bool {
	return staticAssetExts[strings.ToLower(path.Ext(u.Path))]
}

func CanonicalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "" {
		u.Scheme = strings.ToLower(u.Scheme)
	}
	u.Fragment = ""
	if u.Host != "" {
		u.Host = strings.ToLower(u.Host)
	}
	if u.Port() == "80" && u.Scheme == "http" {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	if u.Port() == "443" && u.Scheme == "https" {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}
	if len(u.Path) > 1 && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	return u.String()
}

func (c *Crawler) Crawl(startURL string) []core.CrawlResult {
	if p, err := url.Parse(startURL); err == nil {
		c.baseHost = p.Host
	}
	if norm := CanonicalURL(startURL); norm != "" {
		startURL = norm
	}
	startURL, fbExtras := c.indexFallback(startURL)

	type job struct {
		u string
	}
	type out struct {
		j     job
		links []string
		cr    core.CrawlResult
		err   error
	}

	workers := c.cfg.Threads
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}

	jobs := make(chan job)
	resCh := make(chan out)
	for i := 0; i < workers; i++ {
		go func() {
			for j := range jobs {
				links, forms, err := c.fetchPage(j.u)
				if err == nil && !c.cfg.Verbose {
					output.CrawlingURL(j.u)
				}
				resCh <- out{j: j, links: links, cr: core.CrawlResult{URL: j.u, Forms: forms}, err: err}
			}
		}()
	}

	var results []core.CrawlResult
	queue := []job{{u: startURL}}
	if startURL != "" {
		c.visited[startURL] = true
		if su, err := url.Parse(startURL); err == nil {
			c.sigAdd(su)
		}
	}
	if !c.cfg.BasicCrawl {
		seeded := 0
		for _, s := range fbExtras {
			norm := CanonicalURL(s)
			if norm == "" || c.visited[norm] || !c.IsInScope(norm) {
				continue
			}
			if su, err := url.Parse(norm); err == nil && !c.sigAdd(su) {
				continue
			}
			c.visited[norm] = true
			queue = append(queue, job{u: norm})
			seeded++
			if seeded >= 500 {
				break
			}
		}
		for _, s := range c.seedDiscovery(startURL) {
			norm := CanonicalURL(s)
			if norm == "" || c.visited[norm] || !c.IsInScope(norm) {
				continue
			}
			if su, err := url.Parse(norm); err == nil && !c.sigAdd(su) {
				continue
			}
			c.visited[norm] = true
			queue = append(queue, job{u: norm})
			seeded++
			if seeded >= 500 {
				break
			}
		}
	}
	head := 0
	active := 0
	inFlight := make(map[string]bool)

	for head < len(queue) || active > 0 {
		for active < workers && head < len(queue) {
			item := queue[head]
			head++
			if c.cfg.Exclude != "" && strings.Contains(item.u, c.cfg.Exclude) {
				continue
			}
			if c.cfg.MaxPages > 0 && len(results) >= c.cfg.MaxPages {
				if c.cfg.Verbose {
					output.Verbose("[crawl] --max-pages limit (%d) reached", c.cfg.MaxPages)
				}
				break
			}
			if c.cfg.Verbose {
				output.Verbose("[crawl] %s", item.u)
			}
			inFlight[item.u] = true
			jobs <- job{u: item.u}
			active++
		}

		if active == 0 {
			break
		}

		d := <-resCh
		active--
		delete(inFlight, d.j.u)
		if d.err != nil {
			if c.cfg.Verbose {
				output.Verbose("[crawl-err] %v", d.err)
			}
			continue
		}
		if c.cfg.MaxPages > 0 && len(results) >= c.cfg.MaxPages {
			if c.cfg.Verbose {
				output.Verbose("[crawl] --max-pages limit (%d) reached — dropping extra result", c.cfg.MaxPages)
			}
			continue
		}
		results = append(results, d.cr)
		if c.OnPage != nil {
			c.OnPage(d.cr, len(results))
		}

		if c.cfg.BasicCrawl {
			continue
		}
		remaining := -1
		if c.cfg.MaxPages > 0 {
			remaining = c.cfg.MaxPages - len(results)
		}
		for _, lnk := range d.links {
			if c.cfg.MaxPages > 0 && remaining <= 0 {
				break
			}
			norm := CanonicalURL(lnk)
			if norm == "" || c.visited[norm] || !c.IsInScope(norm) {
				continue
			}
			if su, perr := url.Parse(norm); perr == nil && !c.sigAdd(su) {
				continue
			}
			c.visited[norm] = true
			queue = append(queue, job{u: norm})
			if remaining > 0 {
				remaining--
			}
		}

		if head > 1000 && head*2 >= len(queue) {
			queue = append([]job(nil), queue[head:]...)
			head = 0
		}
		if len(c.visited) > 100000 {
			nv := make(map[string]bool, len(queue)-head+len(results)+len(inFlight))
			for _, q := range queue[head:] {
				nv[q.u] = true
			}
			for _, r := range results {
				nv[r.URL] = true
			}
			for u := range inFlight {
				nv[u] = true
			}
			c.visited = nv
			if c.cfg.Verbose {
				output.Verbose("[crawl] visited map compacted to %d entries", len(nv))
			}
		}
		if len(c.sigSeen) > 200000 {
			c.sigSeen = make(map[string]int)
		}
	}
	close(jobs)
	output.Success("Crawled %d page(s), %d form(s)", len(results), countForms(results))
	return results
}

func (c *Crawler) fetchPage(pageURL string) ([]string, []core.Form, error) {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return nil, nil, err
	}
	core.ApplyHeaders(req, c.cfg)

	client := *c.client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		if isBinaryURLPath(req.URL.Path) {
			return http.ErrUseLastResponse
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			if lu, perr := url.Parse(loc); perr == nil && isBinaryURLPath(lu.Path) {
				return nil, nil, fmt.Errorf("redirect to binary (%s)", loc)
			}
		}
	}
	ct := resp.Header.Get("Content-Type")
	if isBinaryContentType(ct) {
		return nil, nil, fmt.Errorf("not HTML (%s)", ct)
	}

	bs := core.ReadBody(resp.Body)
	links := c.extractLinks(bs, pageURL)
	links = append(links, c.jsEndpoints(pageURL, bs)...)
	forms := ExtractForms(bs, pageURL)
	if c.cfg.JSCrawl && core.EnsureChrome() != "" {
		jl, jf := c.jsRender(pageURL)
		links = append(links, jl...)
		forms = append(forms, jf...)
	}

	finalURL := pageURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	if !c.IsInScope(finalURL) {
		if c.cfg.Verbose {
			output.Verbose("[crawl] %s redirected out of scope (%s) — dropping links/forms", pageURL, finalURL)
		}
		links = nil
		forms = nil
	} else {
		keep := forms[:0]
		for _, f := range forms {
			if c.IsInScope(f.Action) {
				keep = append(keep, f)
			}
		}
		forms = keep
	}
	return links, forms, nil
}

func (c *Crawler) jsEndpoints(pageURL string, body string) []string {
	p, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	base, _ := url.Parse(pageURL)
	var out []string
	seen := map[string]bool{}
	fetched := 0
	for _, m := range jsFileRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 || fetched >= 8 {
			continue
		}
		jsURL := ResolveURL(base, m[1])
		if jsURL == "" {
			continue
		}
		ju, err := url.Parse(jsURL)
		if err != nil || !SameSiteOrSubdomain(ju.Host, p.Host) {
			continue
		}
		jsBody, _, err := core.DoGET(c.client, c.cfg, jsURL)
		if err != nil {
			continue
		}
		fetched++
		for _, re := range jsEndpointPatterns {
			for _, mm := range re.FindAllStringSubmatch(jsBody, -1) {
				if len(mm) < 2 {
					continue
				}
				raw := mm[1]
				if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "#") {
					continue
				}
				if strings.HasPrefix(raw, "http") {
					ru, err := url.Parse(raw)
					if err != nil || !SameSiteOrSubdomain(ru.Host, p.Host) || isStaticAsset(ru) {
						continue
					}
					if !seen[raw] {
						seen[raw] = true
						out = append(out, raw)
					}
					continue
				}
				ref, err := url.Parse(raw)
				if err != nil {
					continue
				}
				full := base.ResolveReference(ref).String()
				if !seen[full] {
					seen[full] = true
					out = append(out, full)
				}
			}
		}
	}
	return out
}

func isBinaryContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	for _, p := range []string{
		"image/", "audio/", "video/", "font/",
		"application/pdf", "application/zip", "application/gzip",
		"application/octet-stream", "application/x-shockwave-flash",
		"application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument",
		"application/msword",
	} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

func isBinaryURLPath(path string) bool {
	path = strings.ToLower(path)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	dot := strings.LastIndexByte(path, '.')
	if dot < 0 {
		return false
	}
	switch path[dot:] {
	case ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".xz", ".bz2",
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
		".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".svg", ".bmp", ".avif",
		".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".webm", ".flv",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".exe", ".dll", ".msi", ".apk", ".deb", ".rpm", ".jar", ".war", ".dmg", ".iso",
		".psd", ".ai", ".sqlite", ".db", ".pem", ".key":
		return true
	}
	return false
}

func (c *Crawler) fetchBody(pageURL string) (string, error) {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return "", err
	}
	core.ApplyHeaders(req, c.cfg)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return core.ReadBody(resp.Body), nil
}

var indexCandidates = []string{
	"/index.html", "/index.htm", "/index.php", "/index.php5", "/index.aspx",
	"/default.asp", "/default.aspx", "/home", "/home.html", "/home.php",
	"/main", "/main.php", "/portal", "/app", "/welcome", "/start",
	"/admin", "/search", "/login", "/dashboard", "/panel", "/api", "/graphql",
}

func (c *Crawler) statusCode(pageURL string) int {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return 0
	}
	core.ApplyHeaders(req, c.cfg)
	resp, err := c.client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func (c *Crawler) indexFallback(startURL string) (string, []string) {
	u, err := url.Parse(startURL)
	if err != nil {
		return startURL, nil
	}
	if u.Path != "" && u.Path != "/" {
		return startURL, nil
	}
	rootStatus := c.statusCode(startURL)
	if rootStatus != 0 && rootStatus < 400 {
		return startURL, nil
	}
	origin := u.Scheme + "://" + u.Host
	start := startURL
	var extra []string
	for _, cand := range indexCandidates {
		candURL := origin + cand
		if st := c.statusCode(candURL); st != 0 && st < 400 {
			if start == startURL {
				output.Info("Root returns %d, crawling from %s instead", rootStatus, candURL)
				start = candURL
			} else {
				extra = append(extra, candURL)
			}
		}
	}
	return start, extra
}

func (c *Crawler) seedDiscovery(startURL string) []string {
	var seeds []string
	base, err := url.Parse(startURL)
	if err != nil {
		return nil
	}
	origin := base.Scheme + "://" + base.Host
	robots, err := c.fetchBody(origin + "/robots.txt")
	if err == nil {
		seeds = append(seeds, c.parseRobots(robots, base)...)
	}
	sm, err := c.fetchBody(origin + "/sitemap.xml")
	if err == nil {
		seeds = append(seeds, c.sitemapSeeds(sm, base, 0)...)
	}
	return seeds
}

func (c *Crawler) parseRobots(body string, base *url.URL) []string {
	var seeds []string
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		low := strings.ToLower(t)
		if strings.HasPrefix(low, "sitemap:") {
			loc := strings.TrimSpace(t[strings.Index(t, ":")+1:])
			seeds = append(seeds, c.sitemapSeedsFromLoc(loc, base, 0)...)
			continue
		}
		if strings.HasPrefix(low, "disallow:") || strings.HasPrefix(low, "allow:") {
			p := strings.TrimSpace(t[strings.Index(t, ":")+1:])
			if p == "" || p == "/" || strings.ContainsAny(p, "*$") {
				continue
			}
			if !strings.HasPrefix(p, "/") {
				continue
			}
			ru := &url.URL{Path: p}
			if i := strings.IndexAny(p, "?#"); i >= 0 {
				ru.Path = p[:i]
				if p[i] == '?' {
					ru.RawQuery = p[i+1:]
				} else {
					ru.Fragment = p[i+1:]
				}
			}
			seeds = append(seeds, base.ResolveReference(ru).String())
		}
	}
	return seeds
}

func (c *Crawler) sitemapSeeds(body string, base *url.URL, depth int) []string {
	var seeds []string
	if depth > 3 {
		return seeds
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return seeds
	}
	doc.Find("sitemap loc").Each(func(_ int, s *goquery.Selection) {
		loc := strings.TrimSpace(s.Text())
		for _, nested := range c.sitemapSeedsFromLoc(loc, base, depth+1) {
			seeds = append(seeds, nested)
		}
	})
	doc.Find("url loc").Each(func(_ int, s *goquery.Selection) {
		if r := ResolveURL(base, strings.TrimSpace(s.Text())); r != "" {
			seeds = append(seeds, r)
		}
	})
	return seeds
}

func (c *Crawler) sitemapSeedsFromLoc(loc string, base *url.URL, depth int) []string {
	if loc == "" || depth > 3 {
		return nil
	}
	r := ResolveURL(base, loc)
	if r == "" {
		return nil
	}
	body, err := c.fetchBody(r)
	if err != nil {
		return nil
	}
	return c.sitemapSeeds(body, base, depth)
}

func (c *Crawler) extractLinks(body, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	linkBase := base
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return nil
	}
	doc.Find("base[href]").Each(func(_ int, s *goquery.Selection) {
		if h, ok := s.Attr("href"); ok && h != "" {
			if rb, perr := url.Parse(ResolveURL(base, h)); perr == nil && rb != nil {
				linkBase = rb
			}
		}
	})
	var links []string
	seen := map[string]bool{}
	doc.Find("a[href], iframe[src], frame[src], area[href]").Each(func(_ int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		if href == "" {
			href, _ = s.Attr("src")
		}
		if href == "" {
			return
		}
		if r := ResolveURL(linkBase, href); r != "" {
			ru, perr := url.Parse(r)
			if perr != nil || isStaticAsset(ru) || !c.IsInScope(r) || seen[r] {
				return
			}
			seen[r] = true
			links = append(links, r)
		}
	})
	doc.Find("meta[http-equiv]").Each(func(_ int, s *goquery.Selection) {
		eq, _ := s.Attr("http-equiv")
		if !strings.EqualFold(eq, "refresh") {
			return
		}
		content, _ := s.Attr("content")
		low := strings.ToLower(content)
		i := strings.Index(low, "url=")
		if i < 0 {
			return
		}
		target := strings.TrimSpace(content[i+4:])
		if r := ResolveURL(linkBase, target); r != "" {
			ru, perr := url.Parse(r)
			if perr != nil || isStaticAsset(ru) || !c.IsInScope(r) || seen[r] {
				return
			}
			seen[r] = true
			links = append(links, r)
		}
	})
	return links
}

func ExtractForms(body, baseURL string) []core.Form {
	var forms []core.Form
	base, _ := url.Parse(baseURL)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return forms
	}
	metaTokenName, metaTokenValue := metaCSRFToken(doc)
	linkBase := base
	doc.Find("base[href]").Each(func(_ int, s *goquery.Selection) {
		if h, ok := s.Attr("href"); ok && h != "" {
			if rb, perr := url.Parse(ResolveURL(base, h)); perr == nil && rb != nil {
				linkBase = rb
			}
		}
	})
	doc.Find("form").Each(func(_ int, sel *goquery.Selection) {
		f := core.Form{Action: baseURL, Method: "GET"}
		if action, ok := sel.Attr("action"); ok && action != "" {
			if r := ResolveURL(linkBase, action); r != "" {
				f.Action = r
			}
		}
		if m, ok := sel.Attr("method"); ok {
			f.Method = strings.ToUpper(strings.TrimSpace(m))
			if f.Method == "" {
				f.Method = "GET"
			}
		}

		sel.Find("input, textarea, select").Each(func(_ int, el *goquery.Selection) {
			inp := core.Input{Type: "text", Value: "fuzz"}
			if n, ok := el.Attr("name"); ok {
				inp.Name = n
			}
			if t, ok := el.Attr("type"); ok {
				inp.Type = strings.ToLower(t)
			}
			if v, ok := el.Attr("value"); ok {
				inp.Value = v
			}
			skip := inp.Name == "" ||
				inp.Type == "submit" || inp.Type == "reset" ||
				inp.Type == "button" || inp.Type == "image"
			if !skip {
				if inp.Type == "hidden" && isCSRFTokenInput(inp.Name, inp.Value) {
					f.TokenName = inp.Name
					f.TokenValue = inp.Value
					return
				}
				f.Inputs = append(f.Inputs, inp)
			}
		})

		if f.TokenName == "" && metaTokenName != "" {
			f.TokenName = metaTokenName
			f.TokenValue = metaTokenValue
		}

		if len(f.Inputs) > 0 {
			forms = append(forms, f)
		}
	})
	return forms
}

func metaCSRFToken(doc *goquery.Document) (string, string) {
	metaTokenName := ""
	metaTokenValue := ""
	doc.Find("meta").Each(func(_ int, sel *goquery.Selection) {
		if metaTokenName != "" {
			return
		}
		if n, ok := sel.Attr("name"); ok && strings.EqualFold(strings.TrimSpace(n), "csrf-token") {
			if c, ok := sel.Attr("content"); ok && strings.TrimSpace(c) != "" {
				metaTokenName = "_token"
				metaTokenValue = strings.TrimSpace(c)
			}
		}
	})
	return metaTokenName, metaTokenValue
}

func isCSRFTokenInput(name, value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	low := strings.ToLower(name)
	return strings.Contains(low, "csrf") ||
		strings.Contains(low, "xsrf") ||
		strings.Contains(low, "authenticity") ||
		strings.Contains(low, "verificationtoken") ||
		low == "token" ||
		strings.HasSuffix(low, "_token")
}

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
		strings.HasPrefix(href, "vbscript:") ||
		strings.HasPrefix(href, "data:") ||
		strings.HasPrefix(href, "file:") ||
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

func hostnameOnly(host string) string {
	h := host
	if i := strings.LastIndexByte(h, ':'); i >= 0 && (strings.Contains(h, "]") == false || i > strings.LastIndexByte(h, ']')) {
		h = h[:i]
	}
	return strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
}

func SameSiteOrSubdomain(host, baseHost string) bool {
	host = hostnameOnly(host)
	baseHost = hostnameOnly(baseHost)
	return host == baseHost || strings.HasSuffix(host, "."+baseHost)
}

func (c *Crawler) IsInScope(link string) bool {
	p, err := url.Parse(link)
	if err != nil {
		return false
	}
	host := p.Host

	for _, pat := range c.cfg.OutOfScope {
		if MatchScope(pat, host, link) {
			return false
		}
	}

	if len(c.cfg.Scope) > 0 {
		for _, pat := range c.cfg.Scope {
			if MatchScope(pat, host, link) {
				return true
			}
		}
		return false
	}

	return SameSiteOrSubdomain(host, c.baseHost)
}

func MatchScope(pattern, host, fullURL string) bool {
	pat := strings.TrimSpace(pattern)
	if pat == "" {
		return false
	}
	var patHost, patPath string
	if i := strings.Index(pat, "://"); i >= 0 {
		rest := pat[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			patHost, patPath = rest[:j], rest[j:]
		} else {
			patHost = rest
		}
	} else {
		patHost = pat
	}
	wildcard := false
	if strings.HasPrefix(patHost, "*.") {
		wildcard = true
		patHost = patHost[2:]
	}
	patHost = hostnameOnly(patHost)

	u, err := url.Parse(fullURL)
	if err != nil {
		return false
	}
	uHost := hostnameOnly(u.Host)
	if wildcard {
		if !strings.EqualFold(uHost, patHost) && !strings.HasSuffix(uHost, "."+patHost) {
			return false
		}
	} else if !strings.EqualFold(uHost, patHost) {
		return false
	}

	if patPath != "" {
		pp := strings.TrimSuffix(patPath, "*")
		up := u.EscapedPath()
		if up == "" {
			up = "/"
		}
		if !strings.HasPrefix(up, pp) {
			return false
		}
	}
	return true
}

func countForms(results []core.CrawlResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Forms)
	}
	return n
}
