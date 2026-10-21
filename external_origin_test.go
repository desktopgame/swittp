package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestExternalOriginConfiguration(t *testing.T) {
	for _, raw := range []string{"https://device.tail.ts.net", "http://app.example", "https://app.example:8443", "https://127.0.0.1", "https://[::1]"} {
		if _, err := parseExternalOrigin(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{"", "*", "https://*.ts.net", "ftp://app.example", "https://user:pass@app.example", "https://app.example/", "https://app.example/path", "https://app.example?", "https://app.example?q=a", "https://app.example#", "https://app.example#x", "https://APP.example", " https://app.example", "https://app.example:", "https://app.example:0", "https://app.example:65536", "https://app.example:443", "http://app.example:80", "https://app.example:08443", "https://bad_host", "https://-bad.example", "https://app..example", "https://app.example.", "https://[fe80::1%25eth0]", "https://app.example\\evil", "https://[example]:8443", "https://[127.0.0.1]", "https://127.1", "https://0x7f000001", "https://256.1.1.1"} {
		if _, err := parseExternalOrigin(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, origins := range [][]string{{"https://app.example", "http://app.example"}, {"https://app.example", "https://app.example"}, {"https://127.0.0.1:8787"}, {"http://localhost:8787"}} {
		_, err := newApp(config{Listen: "127.0.0.1:8787", ExternalOrigins: origins, Services: []service{{ID: "s0", Name: "mock", URL: "http://127.0.0.1:1"}}})
		if err == nil {
			t.Errorf("accepted conflicting origins %v", origins)
		}
	}
	c, err := loadConfig("config.tailscale.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newApp(c); err != nil {
		t.Fatal(err)
	}
}

// HTTP mock of TLS termination: external Host/Origin survive an HTTP-only proxy hop.
// This test does not exercise a browser or a running Tailscale daemon.
func TestExternalHTTPSViaLoopbackProxy(t *testing.T) {
	const host = "device.tail.ts.net"
	const origin = "https://" + host
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Host") != host || r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Error("incorrect external context", r.Header)
		}
		if r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Forwarded-Prefix") != "" || r.Header.Get("X-Real-IP") != "" {
			t.Error("untrusted forwarding metadata leaked", r.Header)
		}
		if r.Host == host || r.Header.Get("Origin") != origin {
			t.Error("unexpected Host/Origin", r.Host, r.Header.Get("Origin"))
		}
		if _, err := r.Cookie(cookieName); err != http.ErrNoCookie {
			t.Error("session cookie leaked")
		}
		fmt.Fprint(w, r.URL.RequestURI())
	}))
	defer upstream.Close()
	a, err := newApp(config{Listen: "127.0.0.1:8787", ExternalOrigins: []string{origin, "http://other.example:8088"}, Services: []service{{ID: "s0", Name: "Mock", URL: upstream.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.proxies["s0"].Transport.(*http.Transport).CloseIdleConnections()
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Error("expected HTTP backend hop")
		}
		a.ServeHTTP(w, r)
	}))
	defer inner.Close()
	target, _ := url.Parse(inner.URL)
	front := httptest.NewServer(httputil.NewSingleHostReverseProxy(target))
	defer front.Close()
	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(method, path, requestHost, requestOrigin, form string, ck *http.Cookie) (*http.Response, string) {
		t.Helper()
		r, _ := http.NewRequest(method, front.URL+path, strings.NewReader(form))
		r.Host = requestHost
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Forwarded-Host", "evil.example")
		r.Header.Set("X-Forwarded-Proto", "http")
		r.Header.Set("Forwarded", "host=evil.example;proto=http")
		r.Header.Set("X-Forwarded-Prefix", "/evil")
		r.Header.Set("X-Real-IP", "evil")
		if ck != nil {
			r.AddCookie(ck)
		}
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return res, string(b)
	}
	page, body := send("GET", "/switch", host, "", "", nil)
	if page.StatusCode != 200 {
		t.Fatal(page.StatusCode, body)
	}
	ck := page.Cookies()[0]
	if !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Domain != "" {
		t.Fatal("unsafe cookie", ck)
	}
	match := regexp.MustCompile(`name="csrf" value="([a-f0-9]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("missing CSRF token")
	}
	form := url.Values{"csrf": {match[1]}, "service": {"s0"}}.Encode()
	for _, invalidOrigin := range []string{"", "null", "https://evil.example", "http://" + host, "http://other.example:8088"} {
		res, _ := send("POST", "/switch/select", host, invalidOrigin, form, ck)
		if res.StatusCode != 403 {
			t.Errorf("origin %q: %d", invalidOrigin, res.StatusCode)
		}
	}
	res, _ := send("POST", "/switch/select", host, origin, "csrf=bad&service=s0", ck)
	if res.StatusCode != 403 {
		t.Fatal("bad CSRF accepted")
	}
	res, _ = send("GET", "/switch/select", host, origin, "", ck)
	if res.StatusCode != 405 {
		t.Fatal("GET accepted")
	}
	res, _ = send("POST", "/switch/select", host, origin, form, ck)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/" {
		t.Fatal(res)
	}
	res, body = send("GET", "/", host, origin, "", ck)
	if res.StatusCode != 200 || body != "/" {
		t.Fatal(res.StatusCode, body)
	}
	res, body = send("POST", "/api%2Fv1?x=1&x=2", host, origin, "", ck)
	if res.StatusCode != 200 || body != "/api%2Fv1?x=1&x=2" {
		t.Fatal(res.StatusCode, body)
	}
	res, _ = send("GET", "/switch", "unlisted.tail.ts.net", "", "", nil)
	if res.StatusCode != 400 {
		t.Fatal("unlisted host accepted")
	}
	res, _ = send("POST", "/switch/select", "other.example:8088", "http://other.example:8088", form, ck)
	if res.StatusCode != 403 {
		t.Fatal("cross-origin session reuse accepted")
	}
	for _, localHost := range []string{a.config.Listen, "localhost:8787", "other.example:8088"} {
		page, _ := send("GET", "/switch", localHost, "", "", nil)
		if page.StatusCode != 200 || page.Cookies()[0].Secure {
			t.Fatal("HTTP cookie semantics changed", localHost, page)
		}
	}
	r := httptest.NewRequest("POST", "/switch/select", strings.NewReader(form))
	r.Host = host
	r.AddCookie(ck)
	r.Header.Add("Origin", origin)
	r.Header.Add("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("ambiguous Origin accepted")
	}
}
