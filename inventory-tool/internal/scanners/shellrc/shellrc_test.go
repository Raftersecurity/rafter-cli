package shellrc

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

func pickFound(t *testing.T, found []scanners.FoundSecret, key string) scanners.FoundSecret {
	t.Helper()
	for _, f := range found {
		if f.KeyName == key {
			return f
		}
	}
	t.Fatalf("no FoundSecret with KeyName %q in %d results: %+v", key, len(found), found)
	return scanners.FoundSecret{}
}

func writeFixture(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestShellRC_ExportLine(t *testing.T) {
	p := writeFixture(t, "export FOO=bar\n")
	out, err := ScanRC(p)
	if err != nil {
		t.Fatal(err)
	}
	got := pickFound(t, out, "FOO")
	if got.Value != "bar" {
		t.Errorf("Value = %q, want %q", got.Value, "bar")
	}
	if got.Source.SourceType != storage.SourceShellRC {
		t.Errorf("SourceType = %q, want %q", got.Source.SourceType, storage.SourceShellRC)
	}
}

func TestShellRC_CommentedExport(t *testing.T) {
	p := writeFixture(t, "# export FOO=bar\n")
	out, err := ScanRC(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range out {
		if f.KeyName == "FOO" {
			t.Errorf("commented export emitted: %+v", f)
		}
	}
}

func TestShellRC_QuotedExport(t *testing.T) {
	p := writeFixture(t,
		`export DOUBLE="bar baz"`+"\n"+
			`export SINGLE='no $expansion'`+"\n")
	out, err := ScanRC(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := pickFound(t, out, "DOUBLE").Value; got != "bar baz" {
		t.Errorf("DOUBLE: Value = %q, want %q", got, "bar baz")
	}
	if got := pickFound(t, out, "SINGLE").Value; got != "no $expansion" {
		t.Errorf("SINGLE: Value = %q, want %q", got, "no $expansion")
	}
}

func TestShellRC_NotAnExport(t *testing.T) {
	p := writeFixture(t,
		`alias ll="ls -la"`+"\n"+
			"function greet() { echo hi; }\n"+
			"PROMPT='%n@%m'\n"+
			"PLAIN_ASSIGN=foo\n")
	out, err := ScanRC(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("non-export lines emitted: %+v", out)
	}
}

func TestShellRC_MixedFixture(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", ".zshrc"))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(dst, src, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := ScanRC(dst)
	if err != nil {
		t.Fatal(err)
	}

	// We expect: OPENAI_API_KEY, GITHUB_TOKEN, PATH (export PATH=...
	// — yes, this is technically captured; the audit UI flags it).
	// We do NOT expect DISABLED_TOKEN.
	want := map[string]string{
		"OPENAI_API_KEY": "sk-fake-openai-key-12345",
		"GITHUB_TOKEN":   "ghp_quoted_token_value",
	}
	for k, v := range want {
		got := pickFound(t, out, k)
		if got.Value != v {
			t.Errorf("%s: Value = %q, want %q", k, got.Value, v)
		}
	}
	for _, f := range out {
		if f.KeyName == "DISABLED_TOKEN" {
			t.Errorf("disabled (commented) export emitted: %+v", f)
		}
	}
}

func TestShellRC_NeverMutatesSource(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".zshrc")
	body := "export FOO=bar\n# export QUX=baz\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256([]byte(body))
	if _, err := ScanRC(p); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	after := sha256.Sum256(got)
	if before != after {
		t.Error("ScanRC mutated source")
	}
}

func TestShellRC_MissingFileNoError(t *testing.T) {
	out, err := ScanRC(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("missing file: err = %v", err)
	}
	if len(out) != 0 {
		t.Errorf("missing file: len = %d, want 0", len(out))
	}
}
