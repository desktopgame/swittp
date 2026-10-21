package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPreserveHostPerService(t *testing.T) {
	const host = "dash.tail.ts.net"
	const origin = "https://" + host
	var calls atomic.Int32
	// A strict dash-like backend: forwarded headers cannot grant access.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Forwarded-Host") != host || r.Header.Get("X-Forwarded-Proto") != "https" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "" {
			t.Error("spoofed proxy context reached backend", r.Header)
		}
		if _, err := r.Cookie(cookieName); err != http.ErrNoCookie {
			t.Error("selection cookie leaked")
		}
		w.Header().Set("Observed-Host", r.Host)
		if r.Host != host {
			http.Error(w, "Host mismatch", 400)
			return
		}
		if r.Header.Get("Origin") != origin {
			http.Error(w, "Origin mismatch", 403)
			return
		}
		if r.URL.RequestURI() != "/api/login?x=1" {
			t.Error("request target changed")
		}
		w.WriteHeader(204)
	}))
	defer backend.Close()
	a, err := newApp(config{Listen: "127.0.0.1:8787", ExternalOrigins: []string{origin}, Services: []service{
		{ID: "default", Name: "Default", URL: backend.URL},
		{ID: "dash", Name: "Dash", URL: backend.URL, PreserveHost: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, p := range a.proxies {
			p.Transport.(*http.Transport).CloseIdleConnections()
		}
	}()
	send := func(path, requestHost, requestOrigin, body string, ck *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Host = requestHost
		r.Header.Set("Origin", requestOrigin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Forwarded-Host", "evil.example")
		r.Header.Set("X-Forwarded-Proto", "http")
		r.Header.Set("Forwarded", "host=evil.example")
		r.Header.Set("X-Forwarded-For", "evil")
		r.Header.Set("X-Real-IP", "evil")
		if ck != nil {
			r.AddCookie(ck)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	r := httptest.NewRequest("GET", "/switch", nil)
	r.Host = host
	page := httptest.NewRecorder()
	a.ServeHTTP(page, r)
	if page.Code != 200 {
		t.Fatal(page.Code)
	}
	ck := page.Result().Cookies()[0]
	a.mu.Lock()
	csrf := a.sessions[ck.Value].CSRF
	a.mu.Unlock()
	backendURL, _ := url.Parse(backend.URL)
	for _, id := range []string{"default", "dash", "default"} {
		form := url.Values{"csrf": {csrf}, "service": {id}}.Encode()
		selected := send("/switch/select", host, origin, form, ck)
		if selected.Code != 303 || selected.Header().Get("Location") != "/" {
			t.Fatal("selection failed", selected.Code)
		}
		w := send("/api/login?x=1", host, origin, "", ck)
		wantStatus, wantHost := 400, backendURL.Host
		if id == "dash" {
			wantStatus, wantHost = 204, host
		}
		if w.Code != wantStatus || w.Header().Get("Observed-Host") != wantHost {
			t.Fatalf("%s: status %d, Host %q", id, w.Code, w.Header().Get("Observed-Host"))
		}
	}
	// Select opt-in again and prove validation still happens before contacting it.
	send("/switch/select", host, origin, url.Values{"csrf": {csrf}, "service": {"dash"}}.Encode(), ck)
	for _, tc := range []struct {
		host, origin string
		status       int
	}{
		{"evil.example", origin, 400}, {host, "https://evil.example", 403}, {host, "null", 403},
	} {
		before := calls.Load()
		w := send("/api/login?x=1", tc.host, tc.origin, "", ck)
		if w.Code != tc.status || calls.Load() != before {
			t.Fatal("invalid request reached backend", tc, w.Code)
		}
	}
	if calls.Load() != 3 {
		t.Fatal("requests did not reach only the configured destination", calls.Load())
	}
}
