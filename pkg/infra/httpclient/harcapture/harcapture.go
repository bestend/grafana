package harcapture

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/har"
)

// redactedValue replaces sensitive header/cookie/query values in captured traffic. Diagnostic
// bundles are meant to be shared (often externally), and the capture sits after the middlewares
// that inject auth headers, so credentials must never reach the archive.
const redactedValue = "[REDACTED]"

// sensitiveHeaders (canonical form) have their value redacted in captured HAR entries.
var sensitiveHeaders = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
	"Www-Authenticate":    {},
	"Cookie":              {},
	"Set-Cookie":          {},
	"X-Api-Key":           {},
	"Api-Key":             {},
	"X-Auth-Token":        {},
	"X-Grafana-Id":        {},
	"X-Id-Token":          {},
}

// sensitiveQueryParams (lower-case) have their value redacted in captured request URLs.
var sensitiveQueryParams = map[string]struct{}{
	"api_key":      {},
	"apikey":       {},
	"access_token": {},
	"auth_token":   {},
	"token":        {},
	"password":     {},
	"secret":       {},
	"signature":    {},
	"sig":          {},
}

func redactHeader(name, value string) string {
	if _, ok := sensitiveHeaders[http.CanonicalHeaderKey(name)]; ok {
		return redactedValue
	}
	return value
}

func redactQueryParam(name, value string) string {
	if _, ok := sensitiveQueryParams[strings.ToLower(name)]; ok {
		return redactedValue
	}
	return value
}

type contextKey struct{}

// Buffer collects HTTP request/response pairs as HAR 1.2 entries in memory.
type Buffer struct {
	mu      sync.Mutex
	entries []*har.Entry
}

// WithCapture returns a child context carrying a new Buffer and the buffer itself.
func WithCapture(ctx context.Context) (context.Context, *Buffer) {
	buf := &Buffer{}
	return context.WithValue(ctx, contextKey{}, buf), buf
}

// FromContext returns the Buffer stored in ctx, or nil if absent.
func FromContext(ctx context.Context) *Buffer {
	v, _ := ctx.Value(contextKey{}).(*Buffer)
	return v
}

// AddEntry appends a captured request/response pair. Thread-safe.
func (b *Buffer) AddEntry(req *http.Request, resp *http.Response, started time.Time, elapsed time.Duration) {
	e := buildEntry(req, resp, started, elapsed)
	b.mu.Lock()
	b.entries = append(b.entries, e)
	b.mu.Unlock()
}

// Len returns the number of captured entries. Thread-safe.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}

// ToHAR serializes the captured entries to HAR 1.2 JSON. The entry types come from
// github.com/chromedp/cdproto/har -- the same library the plugin SDK's e2e HAR storage uses -- so
// the output stays replay-compatible with that fixture format.
func (b *Buffer) ToHAR() ([]byte, error) {
	b.mu.Lock()
	entries := make([]*har.Entry, len(b.entries))
	copy(entries, b.entries)
	b.mu.Unlock()

	doc := har.HAR{
		Log: &har.Log{
			Version: "1.2",
			Creator: &har.Creator{Name: "Grafana", Version: "1.0"},
			Entries: entries,
		},
	}
	return json.Marshal(doc)
}

func buildEntry(req *http.Request, resp *http.Response, started time.Time, elapsed time.Duration) *har.Entry {
	reqHeaders := toNameValues(req.Header)

	query := req.URL.Query()
	queryKeys := make([]string, 0, len(query))
	for k := range query {
		queryKeys = append(queryKeys, k)
	}
	sort.Strings(queryKeys)
	queryString := make([]*har.NameValuePair, 0, len(query))
	redactedQuery := url.Values{}
	for _, k := range queryKeys {
		for _, v := range query[k] {
			rv := redactQueryParam(k, v)
			queryString = append(queryString, &har.NameValuePair{Name: k, Value: rv})
			redactedQuery.Add(k, rv)
		}
	}

	// Request.URL embeds the raw query string, so redact sensitive params there too, not just in
	// the queryString array.
	reqURL := *req.URL
	if len(query) > 0 {
		reqURL.RawQuery = redactedQuery.Encode()
	}

	var pd *har.PostData
	var reqBodySize int64
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
			reqBodySize = int64(len(body))
			if len(body) > 0 {
				pd = &har.PostData{
					MimeType: req.Header.Get("Content-Type"),
					Text:     string(body),
				}
			}
		}
	}

	// Content is required by the HAR spec and dereferenced unconditionally by the SDK's replay, so
	// always attach a (possibly empty) Content, even for transport failures with no response body.
	harResp := &har.Response{HeadersSize: -1, Content: &har.Content{}}
	if resp != nil {
		harResp.Status = int64(resp.StatusCode)
		harResp.StatusText = resp.Status
		harResp.HTTPVersion = resp.Proto
		harResp.Headers = toNameValues(resp.Header)
		harResp.Cookies = toCookies(resp.Cookies())
		harResp.RedirectURL = resp.Header.Get("Location")
		if resp.Body != nil {
			// Drain then Close the original transport body so its connection is returned to the
			// idle pool (per the net/http contract), then hand the caller a fresh reader over the
			// captured bytes.
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				// Preserve the original read failure for the caller: replay the captured bytes,
				// then surface the same error rather than silently substituting a truncated body.
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), &errorReader{err: readErr}))
			} else {
				resp.Body = io.NopCloser(bytes.NewReader(body))
			}
			harResp.BodySize = int64(len(body))
			harResp.Content = &har.Content{
				Size:     int64(len(body)),
				MimeType: resp.Header.Get("Content-Type"),
				Text:     string(body),
			}
		}
	}

	waitMs := float64(elapsed.Milliseconds())
	return &har.Entry{
		StartedDateTime: started.UTC().Format(time.RFC3339Nano),
		Time:            waitMs,
		Request: &har.Request{
			Method:      req.Method,
			URL:         reqURL.String(),
			HTTPVersion: req.Proto,
			Headers:     reqHeaders,
			QueryString: queryString,
			Cookies:     toCookies(req.Cookies()),
			PostData:    pd,
			BodySize:    reqBodySize,
			HeadersSize: -1,
		},
		Response: harResp,
		Cache:    &har.Cache{},
		Timings:  &har.Timings{Send: 0, Wait: waitMs, Receive: 0},
	}
}

// toNameValues flattens an http.Header into HAR name/value pairs, emitting one pair per value so
// repeated headers (e.g. multiple Set-Cookie) are preserved, in sorted order for deterministic output.
func toNameValues(h http.Header) []*har.NameValuePair {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]*har.NameValuePair, 0, len(h))
	for _, name := range names {
		for _, v := range h[name] {
			result = append(result, &har.NameValuePair{Name: name, Value: redactHeader(name, v)})
		}
	}
	return result
}

// toCookies converts parsed HTTP cookies into HAR cookie entries (name/value), matching the SDK
// e2e HAR storage output so captured traffic stays replayable by the E2E fixture proxy.
func toCookies(cookies []*http.Cookie) []*har.Cookie {
	// Cookie values are session/auth tokens; keep the name for context but always redact the value.
	result := make([]*har.Cookie, 0, len(cookies))
	for _, c := range cookies {
		result = append(result, &har.Cookie{Name: c.Name, Value: redactedValue})
	}
	return result
}

// errorReader yields the wrapped error on Read. Used to re-surface a response-body read failure to
// the caller after the captured (partial) bytes have been replayed.
type errorReader struct{ err error }

func (r *errorReader) Read([]byte) (int, error) { return 0, r.err }
