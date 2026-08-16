package core

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	maxResponseDump = 8192
	maxRequestBody  = 4096
)

type Exchange struct {
	Method   string
	URL      string
	Status   int
	Request  string
	Response string
	Time     time.Time
}

type Recorder struct {
	mu    sync.Mutex
	ring  []Exchange
	limit int
}

func NewRecorder(limit int) *Recorder {
	if limit <= 0 {
		limit = 256
	}
	return &Recorder{limit: limit}
}

func (r *Recorder) Add(ex Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ring = append(r.ring, ex)
	if len(r.ring) > r.limit {
		r.ring = r.ring[len(r.ring)-r.limit:]
	}
}

func (r *Recorder) Match(method, rawURL string) *Exchange {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var fallback *Exchange
	for i := len(r.ring) - 1; i >= 0; i-- {
		e := r.ring[i]
		if !strings.EqualFold(e.Method, method) {
			continue
		}
		if e.URL == rawURL {
			return &e
		}
		if eu, uerr := url.Parse(e.URL); uerr == nil && samePathAndHost(eu, u) {
			fallback = &e
		}
	}
	return fallback
}

func samePathAndHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Host, b.Host) && a.Path == b.Path && a.RawQuery == b.RawQuery
}

type recorderTransport struct {
	rt  http.RoundTripper
	rec *Recorder
}

func (t *recorderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.rt.RoundTrip(req)
	if err != nil || t.rec == nil {
		return resp, err
	}
	ex := &Exchange{
		Method:   req.Method,
		URL:      req.URL.String(),
		Status:   resp.StatusCode,
		Request:  dumpRequest(req),
		Response: "",
	}
	rec := t.rec
	resp.Body = newRecordingBody(resp.Body, func(buf []byte) {
		ex.Response = dumpResponse(resp, buf)
		ex.Time = time.Now()
		rec.Add(*ex)
	})
	return resp, nil
}

type recordingBody struct {
	rc   io.ReadCloser
	mu   sync.Mutex
	once sync.Once
	done func(buf []byte)
	buf  *bytes.Buffer
}

func (r *recordingBody) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	if n > 0 {
		r.mu.Lock()
		space := maxResponseDump - r.buf.Len()
		if space > 0 {
			if n <= space {
				r.buf.Write(p[:n])
			} else {
				r.buf.Write(p[:space])
			}
		}
		r.mu.Unlock()
	}
	if err != nil {
		r.flush()
	}
	return n, err
}

func (r *recordingBody) Close() error {
	r.flush()
	return r.rc.Close()
}

func (r *recordingBody) flush() {
	r.once.Do(func() {
		r.mu.Lock()
		buf := r.buf.Bytes()
		r.mu.Unlock()
		r.done(buf)
	})
}

func dumpRequest(req *http.Request) string {
	var b strings.Builder
	b.WriteString(req.Method + " " + req.URL.RequestURI() + " " + req.Proto + "\n")
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	b.WriteString("Host: " + host + "\n")
	for k, vs := range req.Header {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	if req.GetBody != nil {
		if body, gerr := req.GetBody(); gerr == nil {
			if buf, rerr := io.ReadAll(io.LimitReader(body, maxRequestBody)); rerr == nil && len(buf) > 0 {
				b.WriteString("\n" + string(buf))
			}
		}
	}
	return b.String()
}

func dumpResponse(resp *http.Response, body []byte) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s %d %s\n", resp.Proto, resp.StatusCode, resp.Status))
	for k, vs := range resp.Header {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	if len(body) > 0 {
		b.WriteString("\n" + string(body))
	}
	return b.String()
}

func newRecordingBody(rc io.ReadCloser, done func([]byte)) *recordingBody {
	return &recordingBody{rc: rc, done: done, buf: &bytes.Buffer{}}
}
