package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
)

const (
	cookieName   = "trove_session"
	headerName   = "X-Trove-Token"
	queryParam   = "token"
	cookiePath   = "/"
	cookieMaxAge = 0 // session cookie
)

// guard is the outermost middleware. Before any token check it enforces
// two browser-trust-boundary rules that a localhost service handling
// plaintext secrets must not skip:
//
//   - Host allowlist (anti-DNS-rebinding). A malicious page can repoint
//     its own DNS to 127.0.0.1 and make the victim's browser connect to
//     this server, but the browser still sends the attacker's Host
//     header. We refuse any Host that isn't loopback, so rebinding never
//     reaches a real handler even if the token were somehow known.
//   - Origin allowlist on state-changing requests. A cross-site fetch
//     carries the attacker's Origin; we reject any mutating request whose
//     Origin is present and not our own loopback origin. Combined with
//     the SameSite=Strict cookie this closes the CSRF path even if the
//     token leaked into a page the user shouldn't have trusted.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validLoopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if isStateChanging(r.Method) {
			if o := r.Header.Get("Origin"); o != "" && !validLoopbackOrigin(o) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isStateChanging reports whether the HTTP method can mutate server
// state. GET/HEAD/OPTIONS are safe; everything else gets the Origin check.
func isStateChanging(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// validLoopbackHost reports whether a Host header targets the loopback
// interface. Port is ignored — the connection already arrived on our
// listener, so only the hostname needs vetting.
func validLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port present
	}
	switch h {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	// Catch other loopback forms (127.0.0.2, etc.) without allowing names.
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// validLoopbackOrigin parses an Origin header and applies the same
// loopback test to its host. A scheme other than http(s) or an
// unparseable value is rejected.
func validLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return validLoopbackHost(u.Host)
}

// requireToken authenticates every request. The session token may arrive via:
//   - ?token=... query string (only on the initial page load from the launcher URL)
//   - X-Trove-Token header (used by the in-page client for API calls)
//   - trove_session cookie (set after a successful query-string auth)
//
// On a successful query-string auth we set the cookie and strip the token from
// the URL so it doesn't linger in browser history.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authedByCookie(r) || s.authedByHeader(r) {
			next.ServeHTTP(w, r)
			return
		}
		if s.authedByQuery(r) {
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    s.token,
				Path:     cookiePath,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   cookieMaxAge,
			})
			// Redirect to a token-less URL so the secret doesn't end up in
			// browser history or the referer header on subsequent navigation.
			redirectURL := *r.URL
			q := redirectURL.Query()
			q.Del(queryParam)
			redirectURL.RawQuery = q.Encode()
			http.Redirect(w, r, redirectURL.RequestURI(), http.StatusSeeOther)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (s *Server) authedByQuery(r *http.Request) bool {
	got := r.URL.Query().Get(queryParam)
	return got != "" && constTimeEq(got, s.token)
}

func (s *Server) authedByHeader(r *http.Request) bool {
	got := r.Header.Get(headerName)
	return got != "" && constTimeEq(got, s.token)
}

func (s *Server) authedByCookie(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return constTimeEq(c.Value, s.token)
}

func constTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
