package fingerprint

import (
	"strings"
	"testing"
)

func TestCompute_Stable(t *testing.T) {
	got1 := Compute("ANTHROPIC_API_KEY", "sk-ant-abc123")
	got2 := Compute("ANTHROPIC_API_KEY", "sk-ant-abc123")
	if got1 != got2 {
		t.Fatalf("fingerprint not stable: %q vs %q", got1, got2)
	}
	if !strings.HasPrefix(got1, Prefix) {
		t.Fatalf("missing %q prefix: %q", Prefix, got1)
	}
	// 32-byte digest = 64 hex chars; +len(Prefix)
	if len(got1) != len(Prefix)+64 {
		t.Fatalf("unexpected length: got %d, want %d", len(got1), len(Prefix)+64)
	}
}

func TestCompute_KnownVector(t *testing.T) {
	// Pin the canonical input form so the hashing scheme can't drift
	// silently. If this test breaks, we've changed the persisted shape of
	// every secret id in the wild — that requires a schema bump, not a
	// quiet update of this constant.
	const want = "blake3:4c75d8f28bdb00496c8eab6ea7ea057c149d32391ce2ea200002fc6afc1cfb2d"
	got := Compute("ANTHROPIC_API_KEY", "sk-ant-abc123")
	if got != want {
		t.Fatalf("fingerprint drift:\n got:  %s\n want: %s", got, want)
	}
}

func TestCompute_DedupAcrossSources(t *testing.T) {
	// Same (key, value) seen in three places must collapse to one entry.
	a := Compute("STRIPE_SECRET", "sk_live_xyz")
	b := Compute("STRIPE_SECRET", "sk_live_xyz")
	c := Compute("STRIPE_SECRET", "sk_live_xyz")
	if a != b || b != c {
		t.Fatalf("dedup broken: %q, %q, %q", a, b, c)
	}
}

func TestCompute_KeySeparatorPreventsCollision(t *testing.T) {
	// Without the NUL separator, ("A", "BC") and ("AB", "C") would hash
	// identically. The separator is the entire reason these two get
	// different ids.
	if Compute("A", "BC") == Compute("AB", "C") {
		t.Fatal("key/value boundary collision: NUL separator missing or ineffective")
	}
}

func TestCompute_DifferentValuesDiffer(t *testing.T) {
	pre := Compute("DB_URL", "postgres://old")
	post := Compute("DB_URL", "postgres://rotated")
	if pre == post {
		t.Fatal("rotation must produce a new fingerprint")
	}
}

func TestCompute_DifferentKeysDiffer(t *testing.T) {
	if Compute("A", "shared-value") == Compute("B", "shared-value") {
		t.Fatal("identical values under different keys must differ")
	}
}

func TestPreview(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"long ASCII secret", "sk-ant-12345678abcdef9999zRfx", "sk-ant-1...zRfx"},
		{"exactly 13 chars (boundary)", "abcdefghijklm", "abcdefgh...jklm"},
		{"exactly 12 chars (too short)", "abcdefghijkl", "..."},
		{"shorter than threshold", "tiny", "..."},
		{"empty", "", "..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Preview(tc.value)
			if got != tc.want {
				t.Fatalf("Preview(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestPreview_NeverContainsFullSecret(t *testing.T) {
	// The preview must always elide at least one character of the value.
	// Anything else means a UI screenshot of the preview leaks the
	// whole secret.
	cases := []string{
		"",
		"a",
		"abcdefghijkl",   // 12: shorter than prefix+suffix
		"abcdefghijklm",  // 13: boundary, 1 char hidden
		"abcdefghijklmn", // 14
		strings.Repeat("x", 200),
	}
	for _, v := range cases {
		got := Preview(v)
		if got == v {
			t.Errorf("Preview(%q) returned the entire value", v)
		}
	}
}

func TestPreview_RuneSafe(t *testing.T) {
	// Multi-byte runes: 8-rune prefix + 4-rune suffix, never split mid-codepoint.
	value := "🔑🔑🔑🔑🔑🔑🔑🔑middle🚀🚀🚀🚀"
	want := "🔑🔑🔑🔑🔑🔑🔑🔑...🚀🚀🚀🚀"
	if got := Preview(value); got != want {
		t.Fatalf("Preview(%q) = %q, want %q", value, got, want)
	}
}
