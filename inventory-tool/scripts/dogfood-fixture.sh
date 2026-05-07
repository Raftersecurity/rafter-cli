#!/usr/bin/env bash
# trove dogfood pass — synthetic HOME, full-flow sanity check, zero-mutations proof.
# Runs against the binary at $TROVE.
set -euo pipefail

TROVE=${TROVE:-/tmp/trove-dogfood}
FIXTURE=${FIXTURE:-/tmp/trove-fixture-home}
RESULTS=${RESULTS:-/tmp/trove-dogfood-results}

rm -rf "$FIXTURE" "$RESULTS"
mkdir -p "$FIXTURE/code/myapp" "$FIXTURE/.aws" "$FIXTURE/.config/gh" "$RESULTS"

# Synthetic secrets — fake but realistic shape.
cat > "$FIXTURE/code/myapp/.env" <<'EOF'
ANTHROPIC_API_KEY=sk-ant-api03-FakeFixtureKey00000000000000000000zRfx
STRIPE_TEST_KEY=sk_test_FakeFixtureKey00000000008qWc
DATABASE_URL=postgres://user:fakepass@localhost:5432/db
SHARED_TOKEN=fake-shared-fixture-token-aaaa
EOF
chmod 0644 "$FIXTURE/code/myapp/.env"

cat > "$FIXTURE/.zshrc" <<'EOF'
export PATH="/usr/local/bin:$PATH"
# personal aliases
alias ll='ls -la'
export GITHUB_TOKEN="ghp_FakeFixtureToken00000000000000000000zzzz"
export OPENAI_API_KEY="sk-fakefixturekey0000000000000000000000openai"
EOF

cat > "$FIXTURE/.aws/credentials" <<'EOF'
[default]
aws_access_key_id = AKIAIOSFAKEFIXTURE12
aws_secret_access_key = fake/fixture/secretkey/0000000000000000+aWS
EOF
chmod 0600 "$FIXTURE/.aws/credentials"

cat > "$FIXTURE/.npmrc" <<'EOF'
//registry.npmjs.org/:_authToken=npm_FakeFixtureToken00000000000000zzzz
EOF

cat > "$FIXTURE/.config/gh/hosts.yml" <<'EOF'
github.com:
  user: dogfood
  oauth_token: gho_FakeFixtureGhToken000000000000000000zzzz
  git_protocol: https
EOF

# Capture initial sha256 manifest of every fixture file.
cd "$FIXTURE"
find . -type f -not -path './.config/trove/*' | sort | xargs sha256sum > "$RESULTS/manifest.before"
cd - >/dev/null

echo "=== Fixture HOME at $FIXTURE — files: $(wc -l < "$RESULTS/manifest.before") ==="

# Pre-seed scan config so we skip the interactive wizard.
mkdir -p "$FIXTURE/.config/trove"
cat > "$FIXTURE/.config/trove/global.json" <<EOF
{
  "version": 1,
  "schema_compat": "kp-v0.9",
  "scan_config": {
    "roots": ["$FIXTURE"],
    "excludes": ["**/.config/trove/**"]
  },
  "telemetry": { "enabled": false },
  "reveal_policy": "session",
  "secrets": []
}
EOF

# Run --rescan to populate the store without UI.
echo "=== Running trove --rescan ==="
HOME="$FIXTURE" XDG_CONFIG_HOME="$FIXTURE/.config" "$TROVE" --rescan 2>&1 | tee "$RESULTS/rescan.log"

echo "=== After scan, store schema check ==="
SCHEMA=$(jq -r '.schema_compat' "$FIXTURE/.config/trove/global.json")
VERSION=$(jq -r '.version' "$FIXTURE/.config/trove/global.json")
SECRETS=$(jq -r '.secrets | length' "$FIXTURE/.config/trove/global.json")
echo "schema_compat=$SCHEMA  version=$VERSION  secrets=$SECRETS"

# Assert no full secret value leaks into the JSON.
echo "=== Checking for secret leakage in global.json ==="
LEAK=0
for raw in \
    "sk-ant-api03-FakeFixtureKey00000000000000000000zRfx" \
    "sk_test_FakeFixtureKey00000000008qWc" \
    "ghp_FakeFixtureToken00000000000000000000zzzz" \
    "sk-fakefixturekey0000000000000000000000openai" \
    "AKIAIOSFAKEFIXTURE12" \
    "fake/fixture/secretkey/0000000000000000+aWS" \
    "npm_FakeFixtureToken00000000000000zzzz" \
    "gho_FakeFixtureGhToken000000000000000000zzzz"; do
  if grep -qF "$raw" "$FIXTURE/.config/trove/global.json"; then
    echo "LEAK: raw value present in global.json: $raw"
    LEAK=1
  fi
done
if [[ $LEAK -eq 0 ]]; then echo "no-leak: no full secret value present in store JSON"; fi

# Assert fingerprints look right.
echo "=== Sample fingerprint shape ==="
jq -r '.secrets[0:3] | .[] | "key=\(.key_name) id=\(.id) preview=\(.value_preview)"' "$FIXTURE/.config/trove/global.json"

# Boot trove server (non-interactive: --no-open, low timeout) and drive the API.
echo "=== Booting trove HTTP server ==="
HOME="$FIXTURE" XDG_CONFIG_HOME="$FIXTURE/.config" "$TROVE" --no-open --idle-timeout 90s 2> "$RESULTS/server.stderr" &
TROVE_PID=$!
sleep 1

URL=$(awk '/serving on/ {print $NF}' "$RESULTS/server.stderr" | head -1)
TOKEN=$(echo "$URL" | sed 's/.*token=//')
HOSTPORT=$(echo "$URL" | sed 's|http://||;s|/.*||')
BASE="http://$HOSTPORT"
HDR="-H X-Trove-Token:$TOKEN"
echo "URL: $URL"

# 1. List secrets
SC=$(curl -s -o "$RESULTS/secrets.json" -w '%{http_code}' $HDR "$BASE/api/secrets")
COUNT=$(jq -r '.secrets // . | length' "$RESULTS/secrets.json")
echo "GET  /api/secrets: $SC  ($COUNT entries)"

# 2. Reveal three values from different sources
TEST_IDS=$(jq -r '.secrets // . | .[0:3] | .[] | .id' "$RESULTS/secrets.json")
i=0
for ID in $TEST_IDS; do
  i=$((i+1))
  SC=$(curl -s -o "$RESULTS/reveal-$i.json" -w '%{http_code}' -X POST $HDR "$BASE/api/secrets/$ID/reveal")
  HAS=$(jq -r '.value | type' "$RESULTS/reveal-$i.json" 2>/dev/null || echo none)
  echo "POST /api/secrets/$ID/reveal: $SC  value-type=$HAS"
done

# 3. Annotate one
TEST_ID=$(jq -r '.secrets // . | .[0].id' "$RESULTS/secrets.json")
SC=$(curl -s -o "$RESULTS/annotate.json" -w '%{http_code}' -X PATCH $HDR \
  -H "Content-Type: application/json" \
  -d '{"notes":"dogfood test note","tags":["dogfood","fixture"],"source_url":"https://example.com/keys","rotate_url":"https://example.com/rotate"}' \
  "$BASE/api/secrets/$TEST_ID")
echo "PATCH /api/secrets/$TEST_ID: $SC"

# 4. Mark one stale, one rotated
STALE_ID=$(jq -r '.secrets // . | .[1].id' "$RESULTS/secrets.json")
ROTATED_ID=$(jq -r '.secrets // . | .[2].id' "$RESULTS/secrets.json")
SC=$(curl -s -o "$RESULTS/stale.json" -w '%{http_code}' -X POST $HDR "$BASE/api/secrets/$STALE_ID/stale")
echo "POST /api/secrets/$STALE_ID/stale: $SC"
SC=$(curl -s -o "$RESULTS/rotated.json" -w '%{http_code}' -X POST $HDR "$BASE/api/secrets/$ROTATED_ID/rotated")
echo "POST /api/secrets/$ROTATED_ID/rotated: $SC"

# 5. Subscribe to SSE drift, then mutate one .env value to trigger drift.
echo "=== Triggering drift event ==="
( curl -s -N $HDR "$BASE/api/events" > "$RESULTS/sse.log" ) &
SSE_PID=$!
sleep 1
# The TEST mutates the file, not trove. This is the drift trigger.
sed -i 's/SHARED_TOKEN=fake-shared-fixture-token-aaaa/SHARED_TOKEN=fake-shared-fixture-token-bbbb/' "$FIXTURE/code/myapp/.env"
sleep 5
kill -INT $SSE_PID 2>/dev/null || true
wait $SSE_PID 2>/dev/null || true

DRIFT=$(grep -c '^event:' "$RESULTS/sse.log" || true)
echo "SSE event lines observed: $DRIFT"
head -20 "$RESULTS/sse.log"

# Tell trove to exit (close beacon)
curl -s -X POST $HDR "$BASE/api/close" >/dev/null || true
wait $TROVE_PID 2>/dev/null || kill $TROVE_PID 2>/dev/null || true

# 6. Final sha256 manifest, compare. The ONLY allowed difference is the .env we mutated.
cd "$FIXTURE"
find . -type f -not -path './.config/trove/*' | sort | xargs sha256sum > "$RESULTS/manifest.after"
cd - >/dev/null

DIFF=$(diff "$RESULTS/manifest.before" "$RESULTS/manifest.after" || true)
echo "=== Source-file mutation audit ==="
if [[ -z "$DIFF" ]]; then
  echo "FAIL: no files changed at all (drift trigger didn't take?)"
elif echo "$DIFF" | grep -q '/code/myapp/.env'; then
  CHANGES=$(echo "$DIFF" | grep -E '^[<>]' | wc -l)
  ENV_CHANGES=$(echo "$DIFF" | grep -E '^[<>]' | grep -c '/code/myapp/.env' || true)
  if [[ $CHANGES -eq 2 && $ENV_CHANGES -eq 2 ]]; then
    echo "PASS: only .env mutated by the test; every other fixture file byte-identical"
  else
    echo "FAIL: unexpected mutations beyond the test-driven .env change:"
    echo "$DIFF"
  fi
else
  echo "FAIL: changes did not include /code/myapp/.env:"
  echo "$DIFF"
fi
