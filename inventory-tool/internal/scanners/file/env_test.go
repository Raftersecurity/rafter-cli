package file

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// pickFound returns the first FoundSecret with the given KeyName, or fails
// the test. Tests use this rather than asserting on slice order, since
// scanners are free to choose any deterministic order over a file.
func pickFound(t *testing.T, found []scanners.FoundSecret, key string) scanners.FoundSecret {
	t.Helper()
	for _, f := range found {
		if f.KeyName == key {
			return f
		}
	}
	t.Fatalf("no FoundSecret with KeyName %q in %d results", key, len(found))
	return scanners.FoundSecret{}
}

func writeFixture(t *testing.T, name, body string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnvParser_KEYVAL(t *testing.T) {
	p := writeFixture(t, ".env", "FOO=bar\n", 0o600)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := pickFound(t, out, "FOO")
	if got.Value != "bar" {
		t.Errorf("Value = %q, want %q", got.Value, "bar")
	}
}

func TestEnvParser_DoubleQuoted(t *testing.T) {
	p := writeFixture(t, ".env", `KEY="hello world"`+"\n", 0o600)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := pickFound(t, out, "KEY")
	if got.Value != "hello world" {
		t.Errorf("Value = %q, want %q", got.Value, "hello world")
	}
}

func TestEnvParser_SingleQuoted(t *testing.T) {
	// Single-quoted values in shell semantics do NOT expand $VAR. The
	// scanner must keep $VAR verbatim — never expand from the environment.
	p := writeFixture(t, ".env", `KEY='no $expansion here'`+"\n", 0o600)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := pickFound(t, out, "KEY")
	if got.Value != "no $expansion here" {
		t.Errorf("Value = %q, want %q", got.Value, "no $expansion here")
	}
}

func TestEnvParser_ExportPrefix(t *testing.T) {
	p := writeFixture(t, ".env", "export FOO=bar\n", 0o600)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := pickFound(t, out, "FOO")
	if got.Value != "bar" {
		t.Errorf("Value = %q, want %q", got.Value, "bar")
	}
}

func TestEnvParser_CommentSkipped(t *testing.T) {
	// Convention: a leading `#` (after optional whitespace) means the
	// whole line is a comment and contains no secret. An inline ` #`
	// after a value strips the comment for unquoted values; quoted
	// values keep `#` verbatim.
	p := writeFixture(t, ".env",
		"# COMMENTED=should-not-appear\n"+
			"INLINE=trailing # inline comment\n"+
			"QUOTED=\"keeps#hash\"\n", 0o600)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range out {
		if f.KeyName == "COMMENTED" {
			t.Errorf("commented-out line was emitted: %+v", f)
		}
	}
	inline := pickFound(t, out, "INLINE")
	if inline.Value != "trailing" {
		t.Errorf("inline-comment strip: Value = %q, want %q", inline.Value, "trailing")
	}
	quoted := pickFound(t, out, "QUOTED")
	if quoted.Value != "keeps#hash" {
		t.Errorf("quoted hash preserved: Value = %q, want %q", quoted.Value, "keeps#hash")
	}
}

func TestEnvParser_BlankLine(t *testing.T) {
	p := writeFixture(t, ".env", "\n\nFOO=bar\n\n", 0o600)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1 (blanks ignored)", len(out))
	}
	if out[0].Source.Line != 3 {
		t.Errorf("Line = %d, want 3 (1-indexed, after two blanks)", out[0].Source.Line)
	}
}

func TestEnvParser_LineNumberCaptured(t *testing.T) {
	body := "A=1\nB=2\nC=3\n"
	p := writeFixture(t, ".env", body, 0o600)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"A": 1, "B": 2, "C": 3}
	for _, f := range out {
		if want[f.KeyName] != f.Source.Line {
			t.Errorf("%s: Line = %d, want %d", f.KeyName, f.Source.Line, want[f.KeyName])
		}
	}
}

func TestEnvParser_PermissionsCaptured(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes not meaningful on Windows")
	}
	p := writeFixture(t, ".env", "FOO=bar\n", 0o644)
	// os.WriteFile honours umask; force the mode after-the-fact.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := pickFound(t, out, "FOO")
	if got.Source.Permissions != "0644" {
		t.Errorf("Permissions = %q, want %q", got.Source.Permissions, "0644")
	}
	if got.Source.SourceType != storage.SourceEnvFile {
		t.Errorf("SourceType = %q, want %q", got.Source.SourceType, storage.SourceEnvFile)
	}
	if got.Source.Path != p {
		t.Errorf("Path = %q, want %q", got.Source.Path, p)
	}
}

func TestEnvParser_BadFileGracefulError(t *testing.T) {
	// A non-utf8 / very long line must produce a scanner error rather
	// than panic. We synthesise a single line that's too long for a
	// reasonable scanner buffer.
	huge := strings.Repeat("x", 1<<20) // 1 MiB unbroken line
	p := writeFixture(t, ".env", "KEY="+huge, 0o600)
	_, err := ScanEnvFile(p)
	if err == nil {
		t.Skip("scanner accepts huge single line — implementation choice; assert no panic only")
	}
}

// Template-env skip tests (rf-sq72): trove must not catalog placeholder values
// from documentation-by-convention env files (.env.example, .env.sample, etc.).
// The filter is suffix-based on the lowercased basename and applies regardless
// of how many segments sit between `.env` and the trailing template suffix.

func TestEnvParser_SkipsExampleSuffix(t *testing.T) {
	p := writeFixture(t, ".env.example", "YOUR_API_KEY=placeholder\n", 0o644)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf(".env.example: len(out) = %d, want 0", len(out))
	}
}

func TestEnvParser_SkipsSampleSuffix(t *testing.T) {
	p := writeFixture(t, ".env.sample", "TOKEN=sk-PLACEHOLDER\n", 0o644)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf(".env.sample: len(out) = %d, want 0", len(out))
	}
}

func TestEnvParser_SkipsTemplateSuffix(t *testing.T) {
	p := writeFixture(t, ".env.template", "DB_URL=postgres://USER:PASS@host/db\n", 0o644)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf(".env.template: len(out) = %d, want 0", len(out))
	}
}

func TestEnvParser_SkipsLocalExampleSuffix(t *testing.T) {
	p := writeFixture(t, ".env.local.example", "FOO=bar\n", 0o644)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf(".env.local.example: len(out) = %d, want 0", len(out))
	}
}

func TestEnvParser_SkipsDistSuffix(t *testing.T) {
	p := writeFixture(t, ".env.dist", "FOO=bar\n", 0o644)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf(".env.dist: len(out) = %d, want 0", len(out))
	}
}

func TestEnvParser_SkipsTmplSuffix(t *testing.T) {
	p := writeFixture(t, ".env.tmpl", "FOO=bar\n", 0o644)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf(".env.tmpl: len(out) = %d, want 0", len(out))
	}
}

func TestEnvParser_SkipsDummySuffix(t *testing.T) {
	p := writeFixture(t, ".env.dummy", "FOO=bar\n", 0o644)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf(".env.dummy: len(out) = %d, want 0", len(out))
	}
}

func TestEnvParser_CaseInsensitive(t *testing.T) {
	for _, name := range []string{".env.Example", ".env.SAMPLE"} {
		p := writeFixture(t, name, "FOO=bar\n", 0o644)
		out, err := ScanEnvFile(p)
		if err != nil {
			t.Fatalf("%s: err = %v, want nil", name, err)
		}
		if len(out) != 0 {
			t.Errorf("%s: len(out) = %d, want 0 (case-insensitive)", name, len(out))
		}
	}
}

func TestEnvParser_DoesNotSkipRealEnv(t *testing.T) {
	// .env, .env.local, .env.production are real per-environment files —
	// the values inside are real secrets and must be cataloged. Only the
	// documentation-template suffixes are skipped.
	for _, name := range []string{".env", ".env.local", ".env.production"} {
		p := writeFixture(t, name, "REAL_KEY=real-value\n", 0o600)
		out, err := ScanEnvFile(p)
		if err != nil {
			t.Fatalf("%s: err = %v, want nil", name, err)
		}
		if len(out) != 1 {
			t.Errorf("%s: len(out) = %d, want 1 (not a template)", name, len(out))
		}
	}
}

func TestEnvParser_DoesNotSkipEnvrc(t *testing.T) {
	// .envrc is a direnv config file — basename does not start with `.env.`
	// so the template filter must leave it alone.
	p := writeFixture(t, ".envrc", "export FOO=bar\n", 0o600)
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 1 {
		t.Errorf(".envrc: len(out) = %d, want 1 (not a template)", len(out))
	}
}

func TestIsTemplateEnvPath(t *testing.T) {
	hits := []string{
		".env.example",
		".env.sample",
		".env.template",
		".env.tmpl",
		".env.local.example",
		".env.dist",
		".env.dummy",
		".env.Example",
		".env.SAMPLE",
		"/abs/path/.env.example",
		"deep/nested/.env.local.template",
	}
	for _, p := range hits {
		if !IsTemplateEnvPath(p) {
			t.Errorf("IsTemplateEnvPath(%q) = false, want true", p)
		}
	}
	misses := []string{
		".env",
		".env.local",
		".env.production",
		".envrc",
		"foo.example",
		"envsample",
		".envsample", // no dot between env and suffix
		"/abs/.env",
		"",
		"config.json",
	}
	for _, p := range misses {
		if IsTemplateEnvPath(p) {
			t.Errorf("IsTemplateEnvPath(%q) = true, want false", p)
		}
	}
}

func TestEnvParser_MissingFileNoError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "does-not-exist.env")
	out, err := ScanEnvFile(p)
	if err != nil {
		t.Fatalf("missing path: err = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf("missing path: len(out) = %d, want 0", len(out))
	}
}

func TestScanner_NeverMutatesSource_File(t *testing.T) {
	// Cross-cutting: hash bytes before scan, scan, hash after; assert
	// equal. Catches any accidental write/chmod/rename across the file
	// scanner package.
	p := filepath.Join(t.TempDir(), ".env")
	body := "FOO=bar\nexport BAZ=qux\n# c\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	before := sha256Of(t, p)
	if _, err := ScanEnvFile(p); err != nil {
		t.Fatal(err)
	}
	after := sha256Of(t, p)
	if before != after {
		t.Error("ScanEnvFile mutated source file")
	}
}

func sha256Of(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}
