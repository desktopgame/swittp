package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cookieName = "swittp_session"
const sessionTTL = 12 * time.Hour
const maxSessions = 1024

type service struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	PreserveHost bool   `json:"preserve_host,omitempty"`
}

type config struct {
	Listen          string    `json:"listen"`
	Services        []service `json:"services"`
	ExternalOrigins []string  `json:"external_origins,omitempty"`
}

type session struct {
	ID, CSRF, Selected string
	Origin             string
	Expires            time.Time
}

type app struct {
	config   config
	origins  map[string]string // Exact Host -> configured browser origin; never inferred from forwarded headers.
	proxies  map[string]*httputil.ReverseProxy
	mu       sync.Mutex
	sessions map[string]session
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var numericHostLabelPattern = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]+)$`)

// Require the serialized origin browsers send: no path (even /), default port,
// wildcard, credentials or alternate spelling. This makes Host/Origin matching explicit.
func parseExternalOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	invalid := func() (*url.URL, error) {
		return nil, fmt.Errorf("invalid external origin %q: use an exact lowercase http(s) origin without path, credentials, query, fragment or default port", raw)
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || raw != u.Scheme+"://"+u.Host || u.Host != strings.ToLower(u.Host) {
		return invalid()
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if host != ip.String() {
			return invalid()
		}
	} else {
		if strings.ContainsAny(u.Host, "[]") {
			return invalid()
		}
		if len(host) > 253 {
			return invalid()
		}
		labels := strings.Split(host, ".")
		// Browsers interpret numeric final labels as IPv4, sometimes normalizing
		// shorthand, octal or hex spellings. Only canonical IP literals are accepted.
		if numericHostLabelPattern.MatchString(labels[len(labels)-1]) {
			return invalid()
		}
		for _, label := range labels {
			if !dnsLabelPattern.MatchString(label) {
				return invalid()
			}
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return invalid()
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port || (u.Scheme == "http" && p == 80) || (u.Scheme == "https" && p == 443) {
			return invalid()
		}
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if u.Port() != "" {
		authority = net.JoinHostPort(host, u.Port())
	}
	if u.Host != authority {
		return invalid()
	}
	return u, nil
}

func newApp(c config) (*app, error) {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("listen must use a loopback IP and port, e.g. 127.0.0.1:8787")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, errors.New("listen requires a port from 1 to 65535")
	}
	if len(c.Services) == 0 {
		return nil, errors.New("at least one service is required")
	}
	a := &app{config: c, origins: map[string]string{c.Listen: "http://" + c.Listen, net.JoinHostPort("localhost", port): "http://" + net.JoinHostPort("localhost", port)}, proxies: make(map[string]*httputil.ReverseProxy), sessions: make(map[string]session)}
	for _, origin := range c.ExternalOrigins {
		u, err := parseExternalOrigin(origin)
		if err != nil {
			return nil, err
		}
		if _, exists := a.origins[u.Host]; exists {
			return nil, fmt.Errorf("duplicate or conflicting origin host: %s", u.Host)
		}
		a.origins[u.Host] = origin
	}
	for _, s := range c.Services {
		u, err := url.Parse(s.URL)
		if !idPattern.MatchString(s.ID) || a.proxies[s.ID] != nil || s.Name == "" {
			return nil, errors.New("each service needs a unique opaque ID and a name")
		}
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
			return nil, fmt.Errorf("service %s must have an http(s) root URL without credentials, query or fragment", s.ID)
		}
		u.Path, u.RawPath = "", ""
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil // Configuration is authoritative; do not use environment proxies.
		transport.ResponseHeaderTimeout = 30 * time.Second
		a.proxies[s.ID] = &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				// Never accept client-supplied proxy metadata, including nonstandard variants.
				for k := range pr.Out.Header {
					if strings.EqualFold(k, "Forwarded") || strings.HasPrefix(strings.ToLower(k), "x-forwarded-") || strings.EqualFold(k, "X-Real-IP") {
						pr.Out.Header.Del(k)
					}
				}
				pr.SetURL(u)
				if s.PreserveHost {
					// ServeHTTP already validated this Host. The transport destination stays fixed.
					pr.Out.Host = pr.In.Host
				}
				// External context is fixed by configuration, not by caller-supplied proxy headers.
				if external := a.origins[pr.In.Host]; external != "http://"+c.Listen && external != "http://"+net.JoinHostPort("localhost", port) {
					pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
					pr.Out.Header.Set("X-Forwarded-Proto", strings.SplitN(external, ":", 2)[0])
				}
				// SetURL preserves paths; restore raw query even when it contains semicolons.
				pr.Out.URL.RawQuery = pr.In.URL.RawQuery
				pr.Out.Header.Del("Cookie")
				for _, ck := range pr.In.Cookies() {
					if ck.Name != cookieName {
						pr.Out.AddCookie(ck)
					}
				}
				// Avoid reusing a previous service's validators.
				pr.Out.Header.Del("If-None-Match")
				pr.Out.Header.Del("If-Modified-Since")
			},
			FlushInterval: -1, // Flush streaming responses immediately; upgrades use ReverseProxy's tunnel.
			ModifyResponse: func(r *http.Response) error {
				r.Header.Set("Cache-Control", "no-store")
				r.Header.Del("Clear-Site-Data")
				raw := r.Header.Values("Set-Cookie")
				r.Header.Del("Set-Cookie")
				for _, value := range raw {
					ck, err := http.ParseSetCookie(value)
					if err == nil && ck.Name != cookieName {
						r.Header.Add("Set-Cookie", value)
					}
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("upstream %s: %v", s.ID, err)
				http.Error(w, "upstream unavailable", http.StatusBadGateway)
			},
		}
	}
	return a, nil
}

func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (a *app) getSession(r *http.Request) (session, bool) {
	ck, err := r.Cookie(cookieName)
	if err != nil {
		return session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[ck.Value]
	return s, ok && time.Now().Before(s.Expires) && s.Origin == a.origins[r.Host]
}

func (a *app) createSession(w http.ResponseWriter, r *http.Request) (session, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for id, s := range a.sessions {
		if !now.Before(s.Expires) {
			delete(a.sessions, id)
		}
	}
	if len(a.sessions) >= maxSessions {
		http.Error(w, "session capacity reached; try later", http.StatusServiceUnavailable)
		return session{}, false
	}
	origin := a.origins[r.Host]
	s := session{ID: token(), CSRF: token(), Origin: origin, Expires: now.Add(sessionTTL)}
	a.sessions[s.ID] = s
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.ID, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(origin, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	return s, true
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	expectedOrigin, allowed := a.origins[r.Host]
	if !allowed || r.URL.IsAbs() {
		http.Error(w, "invalid host or request target", http.StatusBadRequest)
		return
	}
	// Block cross-site browser requests, including requests to the upstream.
	if origin := r.Header.Get("Origin"); len(r.Header.Values("Origin")) > 1 || (origin != "" && origin != expectedOrigin) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	s, ok := a.getSession(r)
	if r.URL.Path == "/switch" || strings.HasPrefix(r.URL.Path, "/switch/") {
		a.manage(w, r, s, ok)
		return
	}
	if !ok || s.Selected == "" {
		if (r.Method == "GET" || r.Method == "HEAD") && (r.Header.Get("Sec-Fetch-Mode") == "navigate" || strings.Contains(r.Header.Get("Accept"), "text/html")) {
			http.Redirect(w, r, "/switch", http.StatusSeeOther)
		} else {
			http.Error(w, "select a service at /switch", http.StatusConflict)
		}
		return
	}
	a.proxies[s.Selected].ServeHTTP(w, r)
}

var switchPage = template.Must(template.New("switch").Parse(`<!doctype html>
<html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>swittp</title><h1>swittp</h1><p>現在の選択: {{if .Selected}}{{.Selected}}{{else}}未選択{{end}}</p>
<p>同じブラウザのタブは選択を共有します。信頼できるアプリだけを使ってください。</p>
<form method="post" action="/switch/select"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>サービス <select name="service">{{range .Services}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select></label>
<button type="submit">切り替えてルートへ</button></form></html>`))

func (a *app) manage(w http.ResponseWriter, r *http.Request, s session, ok bool) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	switch r.URL.Path {
	case "/switch", "/switch/":
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !ok {
			s, ok = a.createSession(w, r)
			if !ok {
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == "GET" {
			_ = switchPage.Execute(w, struct {
				Selected, CSRF string
				Services       []service
			}{s.Selected, s.CSRF, a.config.Services})
		}
	case "/switch/select":
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !ok || r.Header.Get("Origin") != a.origins[r.Host] {
			http.Error(w, "session and same-origin Origin required", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("csrf") != s.CSRF {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		id := r.PostForm.Get("service")
		if a.proxies[id] == nil {
			http.Error(w, "unknown service", http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		if current, exists := a.sessions[s.ID]; !exists || !time.Now().Before(current.Expires) {
			a.mu.Unlock()
			http.Error(w, "session expired", http.StatusForbidden)
			return
		}
		s.Selected = id
		a.sessions[s.ID] = s
		a.mu.Unlock()
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func loadConfig(path string) (config, error) {
	f, err := os.Open(path)
	if err != nil {
		return config{}, err
	}
	defer f.Close()
	c := config{Listen: "127.0.0.1:8787"}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("config must contain one JSON object")
	}
	return c, nil
}

func main() {
	path := flag.String("config", "config.json", "JSON configuration path")
	flag.Parse()
	c, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	a, err := newApp(c)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: c.Listen, Handler: a, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("swittp: http://%s/switch (loopback only)", c.Listen)
	log.Fatal(srv.ListenAndServe())
}
