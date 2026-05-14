package server

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Smoke tests for the embedded UI's structural contract.
//
// We can't run JS in Go, so these tests assert the most embarrassing
// regressions: someone deletes a feature wholesale (the wordmark, the
// drift ticker, the metrics strip, the perms-warning fix-now hook,
// the reveal-policy taxonomy) and the page silently loses behavior.
//
// Markers are checked against the bytes the server actually serves —
// not the source file on disk — so the embed pipeline is exercised too.

func fetchBody(t *testing.T, url, token string) []byte {
	t.Helper()
	resp, err := http.DefaultClient.Do(authedReq(t, "GET", url, token, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: got %d, want 200", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestIndexHTML_StructuralMarkers locks in the structural pieces of the
// trove UI that downstream behavior depends on. Each marker maps to a
// specific feature; the inline rationale explains what breaks if the
// marker disappears.
func TestIndexHTML_StructuralMarkers(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	body := fetchBody(t, ts.URL+"/", s.token)

	mustContain(t, body, "Rafter",
		"`Rafter` brand mention — required by the brand attribution rule")
	mustContain(t, body, "trove",
		"trove product name — must appear somewhere in the page")
	mustContain(t, body, `aria-live`,
		"aria-live region — screen readers announce drift updates here")
	mustContain(t, body, "drift-badge",
		"drift-badge element — SSE readyState feedback lives here")
	mustContain(t, body, "/static/app.js",
		"app.js script reference — UI is dead without it")
	mustContain(t, body, `id="toast-region"`,
		"toast region — copy/save feedback renders into this node")
	mustContain(t, body, `id="settings-btn"`,
		"settings (gear) button — opens the preferences drawer")
	mustContain(t, body, `id="drawer"`,
		"settings drawer — reveal-policy / auto-rescan / legend live here")
	mustContain(t, body, `id="refresh-btn"`,
		"refresh-scan button — wires to POST /api/rescan")
	mustContain(t, body, `id="watched-list"`,
		"watched-paths sidebar list — file-primary navigation")
}

func TestAppJS_BehaviorMarkers(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	body := fetchBody(t, ts.URL+"/static/app.js", s.token)

	// All four reveal_policy strings must remain present so a future
	// refactor doesn't silently drop a policy mode from the JS taxonomy.
	for _, pol := range []string{"strict", "session", "loose", "paranoid"} {
		mustContain(t, body, pol,
			"reveal_policy string ("+pol+") — required by Inventory-Tool-Spec § Reveal & auth UX")
	}

	// Endpoint references — the JS is dead if any of these drop out.
	for _, ep := range []string{
		"/api/secrets",
		"/api/sources/chmod600",
		"/api/rescan",
		"/api/events",
		"/api/heartbeat",
	} {
		mustContain(t, body, ep,
			"endpoint reference ("+ep+") missing from app.js")
	}

	// Auto-rescan + visibility-aware timer must be present.
	mustContain(t, body, "auto_rescan",
		"auto_rescan localStorage key — auto-rescan preference persistence")
	mustContain(t, body, "document.hidden",
		"document.hidden check — auto-rescan must pause while tab is hidden")

	// The "Notes" rename: only user-visible "Annotate" forbidden.
	for _, forbidden := range []string{
		"\"Annotate\"",
		"'Annotate'",
		">Annotate<",
	} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Errorf("app.js still contains user-visible token %q — rename to \"Notes\" must be complete", forbidden)
		}
	}
}

// TestIndexHTML_RafterPalette pins the Rafter brand hex codes in the CSS
// so a future redesign can't accidentally drop the brand without a test
// breaking. Rafter brand green is the authoritative primary accent
// (badges/README.md); the near-black base matches the Vault Inspector
// reference design at docs/design-refs/.
func TestIndexHTML_RafterPalette(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	body := fetchBody(t, ts.URL+"/", s.token)

	lc := strings.ToLower(string(body))
	for _, hex := range []string{
		"#0a0b0e", // --bg (near-black, matching the Vault Inspector reference)
		"#2ea44f", // --rafter-green (PRIMARY accent — from badges/README.md)
	} {
		if !strings.Contains(lc, hex) {
			t.Errorf("brand palette hex %s missing from index.html — Rafter brand contract broken", hex)
		}
	}

	// Negative assertion: Claude Code orange must NOT reappear as a
	// primary accent. It was the original brand-miss in P13.
	if strings.Contains(lc, "#d97757") {
		t.Errorf("Claude Code orange (#d97757) still present in index.html — brand correction incomplete; primary accent must be Rafter green (#2ea44f)")
	}
}

// TestIndexHTML_MetricsStrip asserts the five-metric strip from the
// Vault Inspector reference design is present. The tile keys are stable
// contracts that JS uses to populate counts and that Playwright tests
// select on.
func TestIndexHTML_MetricsStrip(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	body := fetchBody(t, ts.URL+"/", s.token)

	for _, tile := range []string{
		`data-tile="files"`,
		`data-tile="secrets"`,
		`data-tile="overdue"`,
		`data-tile="soon"`,
		`data-tile="perm"`,
	} {
		mustContain(t, body, tile,
			"metric tile marker "+tile+" — risk dashboard depends on this hook")
	}
	mustContain(t, body, `class="metrics"`,
		"<section class=\"metrics\"> wrapper — the metric tiles live inside this region")
}

func mustContain(t *testing.T, body []byte, needle, reason string) {
	t.Helper()
	if !bytes.Contains(body, []byte(needle)) {
		t.Errorf("expected to find %q in response — %s", needle, reason)
	}
}
