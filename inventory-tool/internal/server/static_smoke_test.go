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
// drift ticker, the mode-octal hook, the data-clear-selection hook,
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

	mustContain(t, body, "trove",
		"wordmark — without it the product loses its name in the header")
	mustContain(t, body, "by ",
		"`by Rafter` subtag — anchors the brand attribution beside the wordmark")
	mustContain(t, body, "Rafter",
		"`Rafter` brand mention — required by the brand attribution rule")
	mustContain(t, body, `aria-live`,
		"aria-live region — screen readers announce drift updates here")
	mustContain(t, body, "data-clear-selection",
		"data-clear-selection hook on #list — JS uses this to find the click-outside zone")
	mustContain(t, body, "drift-badge",
		"drift-badge element — SSE readyState feedback lives here")
	mustContain(t, body, "/static/app.js",
		"app.js script reference — UI is dead without it")
	mustContain(t, body, "id=\"toast-region\"",
		"toast region — copy/save feedback renders into this node")
}

func TestAppJS_BehaviorMarkers(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	body := fetchBody(t, ts.URL+"/static/app.js", s.token)

	mustContain(t, body, "data-mode-octal",
		"mode-octal attribute — Go smoke tests and CSS hooks rely on it; tooltip wiring goes through this")
	mustContain(t, body, "MODE_TIPS",
		"mode-octal tooltip table — explains 0644 / 0640 / 0600 to users who don't know unix perms")

	// All four reveal_policy strings must remain present so a future
	// refactor doesn't silently drop a policy mode from the JS taxonomy.
	for _, pol := range []string{"strict", "session", "loose", "paranoid"} {
		mustContain(t, body, pol,
			"reveal_policy string ("+pol+") — required by Inventory-Tool-Spec § Reveal & auth UX")
	}

	// Endpoint references — the JS is dead if any of these drop out.
	for _, ep := range []string{
		"/api/secrets",
		"/api/secrets/${encodeURIComponent(s.id)}/reveal",
		"annotation",
		"stale",
		"rotated",
		"/api/events",
	} {
		mustContain(t, body, ep,
			"endpoint reference ("+ep+") missing from app.js")
	}

	// The "Notes" rename (was: "Annotate") is a copy-fix that the P9
	// polecat skipped — pin it so it can't silently regress.
	mustContain(t, body, "\"Notes\"",
		"copy fix: section heading should be \"Notes\", not \"Annotate\"")
	// Only user-visible "Annotate" (capitalized, in string-literal
	// contexts) is forbidden. The wire endpoint path /api/.../annotation
	// and internal identifiers like readPanelAnnotation are fine.
	for _, forbidden := range []string{
		"\"Annotate\"",
		"'Annotate'",
		">Annotate<",
		"\"annotate\"",
		"'annotate'",
	} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Errorf("app.js still contains user-visible token %q — rename to \"Notes\" must be complete", forbidden)
		}
	}
}

// TestIndexHTML_RafterPalette pins the Rafter brand hex codes in the CSS
// so a future redesign can't accidentally drop the brand without a test
// breaking. P14 corrected a brand miss: Claude Code orange (#d97757) was
// retired in favour of the authoritative Rafter green (#2ea44f) from
// badges/README.md, paired with a cooler dark base.
func TestIndexHTML_RafterPalette(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	body := fetchBody(t, ts.URL+"/", s.token)

	lc := strings.ToLower(string(body))
	for _, hex := range []string{
		"#0f1115", // --bg (cool-dark security-tool base)
		"#e8edf2", // --fg (cool off-white)
		"#2ea44f", // --rafter-green (PRIMARY accent — from badges/README.md)
	} {
		if !strings.Contains(lc, hex) {
			t.Errorf("brand palette hex %s missing from index.html — Rafter brand contract broken", hex)
		}
	}

	// Negative assertion: the previous-restyle Claude Code orange must
	// NOT appear anywhere. This is the explicit P14 brand-correction
	// guard.
	if strings.Contains(lc, "#d97757") {
		t.Errorf("Claude Code orange (#d97757) still present in index.html — P14 brand correction incomplete; primary accent must be Rafter green (#2ea44f)")
	}
}

// TestIndexHTML_DashboardTiles asserts the P14 risk dashboard's four
// tiles are present on the page. The tile id markers are stable contracts
// that JS uses to populate counts and that Playwright tests select on.
func TestIndexHTML_DashboardTiles(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	body := fetchBody(t, ts.URL+"/", s.token)

	for _, tile := range []string{
		`data-tile="files-scanned"`,
		`data-tile="loose-perms"`,
		`data-tile="env-in-git"`,
		`data-tile="total-secrets"`,
	} {
		mustContain(t, body, tile,
			"dashboard tile marker "+tile+" — P14 risk dashboard depends on this hook")
	}
	mustContain(t, body, `id="dashboard"`,
		"#dashboard section — the four risk tiles live inside this region")
}

func mustContain(t *testing.T, body []byte, needle, reason string) {
	t.Helper()
	if !bytes.Contains(body, []byte(needle)) {
		t.Errorf("expected to find %q in response — %s", needle, reason)
	}
}
