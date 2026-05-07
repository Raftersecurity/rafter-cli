package config

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

func sha256Of(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("testdata", name)
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestAWSCredentials_INI(t *testing.T) {
	p := copyFixture(t, "credentials")
	out, err := ScanAWSCredentials(p)
	if err != nil {
		t.Fatal(err)
	}

	// Two profiles × (2 mandatory fields + 1 optional session token in default)
	wantValues := map[string]string{
		"default.aws_access_key_id":      "AKIAIOSFODNN7EXAMPLE",
		"default.aws_secret_access_key":  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"default.aws_session_token":      "FQoGZXIvYXdzEMK//FAKETOKEN",
		"work.aws_access_key_id":         "AKIAWORKEXAMPLE0000",
		"work.aws_secret_access_key":     "WorkSecretAccessKeyExampleValue000000000",
	}
	for k, want := range wantValues {
		got := pickFound(t, out, k)
		if got.Value != want {
			t.Errorf("%s: Value = %q, want %q", k, got.Value, want)
		}
		if got.Source.SourceType != storage.SourceEnvFile {
			t.Errorf("%s: SourceType = %q, want envfile", k, got.Source.SourceType)
		}
		if got.Source.Path != p {
			t.Errorf("%s: Path = %q, want %q", k, got.Source.Path, p)
		}
	}
}

func TestNpmrc_AuthToken(t *testing.T) {
	p := copyFixture(t, ".npmrc")
	out, err := ScanNpmrc(p)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"//registry.npmjs.org/:_authToken":  "npm_FakeToken123abc456def789ghi",
		"//npm.pkg.github.com/:_authToken":  "ghp_FakeGithubPackagesToken000",
	}
	for k, v := range want {
		got := pickFound(t, out, k)
		if got.Value != v {
			t.Errorf("%s: Value = %q, want %q", k, got.Value, v)
		}
	}
	for _, f := range out {
		if f.KeyName == "email" {
			t.Errorf("email line should not be emitted as a secret: %+v", f)
		}
	}
}

func TestDockerConfig_Auths(t *testing.T) {
	p := copyFixture(t, "docker_config.json")
	out, err := ScanDockerConfig(p)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"https://index.docker.io/v1/.auth": "ZGVtby11c2VyOmZha2UtcGFzc3dvcmQ=",
		"ghcr.io.auth":                     "Z2hjci11c2VyOmZha2UtcGFzc3dvcmQ=",
		"ghcr.io.identitytoken":            "ghcr-identity-token-fake-12345",
	}
	for k, v := range want {
		got := pickFound(t, out, k)
		if got.Value != v {
			t.Errorf("%s: Value = %q, want %q", k, got.Value, v)
		}
	}
}

func TestGhHosts_OAuthToken(t *testing.T) {
	p := copyFixture(t, "hosts.yml")
	out, err := ScanGhHosts(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"github.com.oauth_token":     "gho_FakeGithubOAuthToken000abc123def456",
		"ghe.example.com.oauth_token": "gho_FakeEnterpriseToken99988877766",
	}
	for k, v := range want {
		got := pickFound(t, out, k)
		if got.Value != v {
			t.Errorf("%s: Value = %q, want %q", k, got.Value, v)
		}
	}
	// `user` is metadata, not a secret — must not be emitted.
	for _, f := range out {
		if f.KeyName == "github.com.user" || f.KeyName == "github.com.git_protocol" {
			t.Errorf("non-secret field emitted: %+v", f)
		}
	}
}

func TestClaudeSettings_APIKeyHelper(t *testing.T) {
	p := copyFixture(t, "claude_settings.json")
	out, err := ScanClaudeSettings(p)
	if err != nil {
		t.Fatal(err)
	}

	// Top-level apiKeyHelper plus token-bearing field names anywhere
	// in the document.
	must := map[string]string{
		"apiKeyHelper":             "/usr/local/bin/get-anthropic-key.sh",
		"anthropicApiKey":          "sk-ant-api03-FakeKeyForFixturesOnly0000",
		"env.OPENAI_API_KEY":       "sk-fake-openai-key-for-fixtures-0000",
	}
	for k, v := range must {
		got := pickFound(t, out, k)
		if got.Value != v {
			t.Errorf("%s: Value = %q, want %q", k, got.Value, v)
		}
	}
	// `model` and `permissions.allow` are not credential fields.
	for _, f := range out {
		switch f.KeyName {
		case "model", "env.SOME_NORMAL_VAR":
			t.Errorf("non-credential field emitted: %+v", f)
		}
	}
}

func TestScanner_NeverMutatesSource_Config(t *testing.T) {
	cases := []struct {
		fixture string
		scan    func(string) ([]scanners.FoundSecret, error)
	}{
		{"credentials", ScanAWSCredentials},
		{".npmrc", ScanNpmrc},
		{"docker_config.json", ScanDockerConfig},
		{"hosts.yml", ScanGhHosts},
		{"claude_settings.json", ScanClaudeSettings},
	}
	for _, c := range cases {
		c := c
		t.Run(c.fixture, func(t *testing.T) {
			p := copyFixture(t, c.fixture)
			before := sha256Of(t, p)
			if _, err := c.scan(p); err != nil {
				t.Fatal(err)
			}
			after := sha256Of(t, p)
			if before != after {
				t.Errorf("%s: scanner mutated source", c.fixture)
			}
		})
	}
}

func TestScanner_MissingFileNoError_Config(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	for _, scan := range []func(string) ([]scanners.FoundSecret, error){
		ScanAWSCredentials, ScanNpmrc, ScanDockerConfig, ScanGhHosts, ScanClaudeSettings,
	} {
		out, err := scan(missing)
		if err != nil {
			t.Errorf("missing file: err = %v, want nil", err)
		}
		if len(out) != 0 {
			t.Errorf("missing file: len = %d, want 0", len(out))
		}
	}
}
