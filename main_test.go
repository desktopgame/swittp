package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testApp(t *testing.T, handlers ...http.HandlerFunc) *app {
	t.Helper()
	c := config{Listen: "127.0.0.1:8787"}
	for i, h := range handlers {
		s := httptest.NewServer(h)
		t.Cleanup(s.Close)
		c.Services = append(c.Services, service{ID: fmt.Sprintf("s%d", i), Name: "Mock", URL: s.URL})
	}
	a, err := newApp(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, p := range a.proxies {
			p.Transport.(*http.Transport).CloseIdleConnections()
		}
	})
	return a
}

func request(a *app, method, target string, body io.Reader, ck *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, body)
	r.Host = a.config.Listen
	if ck != nil {
		r.AddCookie(ck)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func browser(t *testing.T, a *app) (*http.Cookie, string) {
	t.Helper()
	w := request(a, "GET", "/switch", nil, nil, nil)
	if w.Code != 200 {
		t.Fatalf("switch: %d", w.Code)
	}
	ck := w.Result().Cookies()[0]
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" {
		t.Fatal("unsafe session cookie")
	}
	a.mu.Lock()
	s := a.sessions[ck.Value]
	a.mu.Unlock()
	if !strings.Contains(w.Body.String(), s.CSRF) {
		t.Fatal("missing csrf form")
	}
	return ck, s.CSRF
}

func selectService(a *app, ck *http.Cookie, csrf, id string) *httptest.ResponseRecorder {
	return request(a, "POST", "/switch/select", strings.NewReader(url.Values{"csrf": {csrf}, "service": {id}}.Encode()), ck, map[string]string{"Origin": "http://" + a.config.Listen, "Content-Type": "application/x-www-form-urlencoded"})
}

func TestRoutingSwitchingAndSessions(t *testing.T) {
	a := testApp(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "a:"+r.URL.RequestURI()) },
		func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "b:"+r.URL.RequestURI()) })
	w := request(a, "GET", "/deep", nil, nil, map[string]string{"Accept": "text/html"})
	if w.Code != 303 || w.Header().Get("Location") != "/switch" {
		t.Fatal(w)
	}
	if w := request(a, "POST", "/api", nil, nil, nil); w.Code != 409 {
		t.Fatal(w.Code)
	}
	ck, csrf := browser(t, a)
	if w := selectService(a, ck, csrf, "s0"); w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatal(w)
	}
	path := "/a%2Fb//c?x=1&x=2&raw=%2f&semi=a;b"
	if w := request(a, "GET", path, nil, ck, nil); w.Body.String() != "a:"+path {
		t.Fatal(w.Body.String())
	}
	if w := selectService(a, ck, csrf, "s1"); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := request(a, "GET", "/", nil, ck, nil); w.Body.String() != "b:/" {
		t.Fatal(w.Body.String())
	}
	if w := request(a, "GET", "/switchboard", nil, ck, nil); w.Body.String() != "b:/switchboard" {
		t.Fatal(w.Body.String())
	}
	if w := request(a, "GET", "/switch/missing", nil, ck, nil); w.Code != 404 {
		t.Fatal(w.Code)
	}
	other, _ := browser(t, a)
	if w := request(a, "GET", "/", nil, other, nil); w.Code != 409 {
		t.Fatal("sessions leaked")
	}
}

func TestManagementSecurity(t *testing.T) {
	a := testApp(t, func(w http.ResponseWriter, r *http.Request) {})
	ck, csrf := browser(t, a)
	for _, tc := range []struct {
		name, method, body, origin string
		cookie                     *http.Cookie
		want                       int
	}{
		{"get", "GET", "", "", ck, 405},
		{"no session", "POST", "csrf=" + csrf + "&service=s0", "http://" + a.config.Listen, nil, 403},
		{"no origin", "POST", "csrf=" + csrf + "&service=s0", "", ck, 403},
		{"foreign origin", "POST", "csrf=" + csrf + "&service=s0", "https://evil.test", ck, 403},
		{"null origin", "POST", "csrf=" + csrf + "&service=s0", "null", ck, 403},
		{"bad token", "POST", "csrf=wrong&service=s0", "http://" + a.config.Listen, ck, 403},
		{"bad id", "POST", "csrf=" + csrf + "&service=http://evil.test", "http://" + a.config.Listen, ck, 400},
		{"oversized", "POST", "csrf=" + csrf + "&service=" + strings.Repeat("a", 5000), "http://" + a.config.Listen, ck, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(a, tc.method, "/switch/select", strings.NewReader(tc.body), tc.cookie, map[string]string{"Origin": tc.origin, "Content-Type": "application/x-www-form-urlencoded"})
			if w.Code != tc.want {
				t.Fatalf("%d want %d", w.Code, tc.want)
			}
		})
	}
	for _, target := range []string{"/", "http://evil.test/"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = "evil.test:8787"
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if w := request(a, "GET", "http://evil.test/", nil, ck, nil); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request(a, "GET", "/switch", nil, ck, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(a, "POST", "/switch", nil, ck, nil); w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestProxyHeadersBodyAndCookies(t *testing.T) {
	a := testApp(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(cookieName); err != http.ErrNoCookie {
			t.Error("selection cookie forwarded")
		}
		if ck, err := r.Cookie("app"); err != nil || ck.Value != "value" {
			t.Error("app cookie missing")
		}
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-forwarded-") || k == "Forwarded" || k == "X-Real-Ip" {
				t.Errorf("spoofed metadata: %s", k)
			}
		}
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			t.Error("cache validator forwarded")
		}
		if r.Host == "127.0.0.1:8787" {
			t.Error("upstream host not set")
		}
		b, _ := io.ReadAll(r.Body)
		w.Header().Add("Set-Cookie", cookieName+"=attack; Path=/")
		w.Header().Add("Set-Cookie", "app=next; Path=/")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Clear-Site-Data", `"*"`)
		w.WriteHeader(201)
		fmt.Fprintf(w, "%s:%s", r.Method, b)
	})
	ck, csrf := browser(t, a)
	selectService(a, ck, csrf, "s0")
	w := request(a, "PUT", "/api", strings.NewReader("payload"), ck, map[string]string{
		"Cookie": cookieName + "=" + ck.Value + "; app=value", "Forwarded": "for=evil", "X-Forwarded-Host": "evil", "X-Forwarded-Prefix": "/evil", "X-Real-IP": "evil",
		"If-None-Match": `"old"`, "If-Modified-Since": "yesterday",
	})
	if w.Code != 201 || w.Body.String() != "PUT:payload" {
		t.Fatal(w)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Clear-Site-Data") != "" {
		t.Fatal(w.Header())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "app" {
		t.Fatal(cookies)
	}
}

func TestBackendFailure(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	backend.Close()
	a, err := newApp(config{Listen: "127.0.0.1:8787", Services: []service{{ID: "s0", Name: "offline", URL: backend.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	ck, csrf := browser(t, a)
	selectService(a, ck, csrf, "s0")
	if w := request(a, "GET", "/", nil, ck, nil); w.Code != 502 {
		t.Fatal(w.Code)
	}
}

func TestStreaming(t *testing.T) {
	release := make(chan struct{})
	a := testApp(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "data: last\n\n")
	})
	ck, csrf := browser(t, a)
	selectService(a, ck, csrf, "s0")
	front := httptest.NewServer(a)
	defer front.Close()
	defer close(release)
	r, _ := http.NewRequest("GET", front.URL+"/events", nil)
	r.Host = a.config.Listen
	r.AddCookie(ck)
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	line, err := bufio.NewReader(res.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("%q %v", line, err)
	}
}

func TestWebSocketUpgradeAndTunnel(t *testing.T) {
	a := testApp(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			t.Error("upgrade lost")
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		rw.Flush()
		// Minimal masked client text frame "hi".
		b := make([]byte, 8)
		if _, err := io.ReadFull(rw, b); err != nil {
			t.Error(err)
			return
		}
		if string(b) != string([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}) {
			t.Error("frame changed")
		}
		rw.Write([]byte{0x81, 2, 'h', 'i'})
		rw.Flush()
	})
	ck, csrf := browser(t, a)
	selectService(a, ck, csrf, "s0")
	front := httptest.NewServer(a)
	defer front.Close()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(front.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nCookie: %s=%s\r\nOrigin: http://%s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", a.config.Listen, cookieName, ck.Value, a.config.Listen)
	reader := bufio.NewReader(conn)
	res, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 101 || res.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal(res)
	}
	conn.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2})
	b := make([]byte, 4)
	if _, err := io.ReadFull(reader, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != string([]byte{0x81, 2, 'h', 'i'}) {
		t.Fatal(b)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, listen := range []string{":8787", "0.0.0.0:8787", "192.168.1.1:8787", "localhost:8787", "127.0.0.1:0", "127.0.0.1:http"} {
		if _, err := newApp(config{Listen: listen, Services: []service{{ID: "s0", Name: "x", URL: "http://127.0.0.1:3000"}}}); err == nil {
			t.Errorf("accepted %s", listen)
		}
	}
	for _, target := range []string{"file:///tmp/a", "http://user:pass@localhost", "http://localhost/sub", "http://localhost?q=x", "http://localhost#x"} {
		if _, err := newApp(config{Listen: "127.0.0.1:8787", Services: []service{{ID: "s0", Name: "x", URL: target}}}); err == nil {
			t.Errorf("accepted %s", target)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	c, err := loadConfig("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newApp(c); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	for _, text := range []string{
		`{"listen":"127.0.0.1:8787","typo":true}`,
		`{} {}`,
		`{"services":`,
	} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatalf("accepted invalid config: %s", text)
		}
	}
}

func TestConcurrentSelectionAndExpiry(t *testing.T) {
	a := testApp(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	ck, csrf := browser(t, a)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); selectService(a, ck, csrf, "s0"); request(a, "GET", "/", nil, ck, nil) }()
	}
	wg.Wait()
	a.mu.Lock()
	s := a.sessions[ck.Value]
	s.Expires = time.Now().Add(-time.Second)
	a.sessions[s.ID] = s
	a.mu.Unlock()
	if w := selectService(a, ck, csrf, "s0"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(a, "GET", "/", nil, ck, nil); w.Code != 409 {
		t.Fatal(w.Code)
	}
}
