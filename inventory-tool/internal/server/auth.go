package server

import (
	"crypto/subtle"
	"net/http"
)

const (
	cookieName   = "trove_session"
	headerName   = "X-Trove-Token"
	queryParam   = "token"
	cookiePath   = "/"
	cookieMaxAge = 0 // session cookie
)

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
