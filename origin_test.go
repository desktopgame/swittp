package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSelectionOriginValidation(t *testing.T) {
	a := testApp(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "upstream reached") })
	for _, tc := range []struct {
		name, origin string
		want         int
	}{
		{"local", "http://127.0.0.1:8787", 303},
		{"form_no_referrer", "null", 403},
		{"https_terminator_rewrites_host", "https://swittp.example.test", 403},
		{"https_same_host", "https://127.0.0.1:8787", 403},
		{"different_local_hostname", "http://localhost:8787", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ck, csrf := browser(t, a)
			form := url.Values{"csrf": {csrf}, "service": {"s0"}}.Encode()
			w := request(a, "POST", "/switch/select", strings.NewReader(form), ck, map[string]string{"Origin": tc.origin, "Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "swittp.example.test"})
			if w.Code != tc.want {
				t.Fatalf("got %d want %d", w.Code, tc.want)
			}
			if tc.want == 403 {
				if w.Body.String() != "cross-origin request rejected\n" || w.Header().Get("Location") != "" {
					t.Fatal(w)
				}
				a.mu.Lock()
				selected := a.sessions[ck.Value].Selected
				a.mu.Unlock()
				if selected != "" {
					t.Fatal("rejected POST changed selection")
				}
			} else {
				if w.Header().Get("Location") != "/" {
					t.Fatal(w)
				}
				root := request(a, "GET", "/", nil, ck, nil)
				if root.Code != 200 || root.Body.String() != "upstream reached" {
					t.Fatal(root)
				}
			}
		})
	}
	r := httptest.NewRequest("POST", "/switch/select", nil)
	r.Host = "swittp.example.test"
	r.Header.Set("Origin", "https://swittp.example.test")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 400 || w.Body.String() != "invalid host or request target\n" {
		t.Fatal(w)
	}
}

func TestUpstreamOriginValidation(t *testing.T) {
	a := testApp(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "%s|%s", r.Host, r.Header.Get("Origin")) })
	ck, csrf := browser(t, a)
	selectService(a, ck, csrf, "s0")
	for _, origin := range []string{"null", "https://swittp.example.test"} {
		w := request(a, "POST", "/api", nil, ck, map[string]string{"Origin": origin})
		if w.Code != 403 || w.Body.String() != "cross-origin request rejected\n" {
			t.Fatal(w)
		}
	}
	w := request(a, "POST", "/api", nil, ck, map[string]string{"Origin": "http://" + a.config.Listen})
	if w.Code != 200 || !strings.HasSuffix(w.Body.String(), "|http://"+a.config.Listen) || strings.HasPrefix(w.Body.String(), a.config.Listen+"|") {
		t.Fatal(w)
	}
}

func TestManagementFormKeepsSameOrigin(t *testing.T) {
	a := testApp(t, func(w http.ResponseWriter, r *http.Request) {})
	w := request(a, "GET", "/switch", nil, nil, nil)
	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("management form needs same-origin policy; got %q (no-referrer makes navigation POST Origin null)", got)
	}
}
