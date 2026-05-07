# trove dogfood report

| | |
|---|---|
| Commit | `8f06a0f` (P7 merge — local) |
| Build | `CGO_ENABLED=0 go build ./cmd/trove` (~9 MB statically linked) |
| Host | linux/amd64, Go 1.22.2 |
| Bead | `rf-vfnl` (P8) |
| Run by | scout (after three polecat sessions bounced on hook resolution) |
| Verdict | **SHIP** |

## Procedure

A synthetic `$HOME` was assembled at `/tmp/trove-fixture-home` with five files
holding eleven realistic-shaped (but fake) secrets:

```
~/code/myapp/.env       4 secrets   (.env)
~/.zshrc                3 lines     (export PATH, GITHUB_TOKEN, OPENAI_API_KEY)
~/.aws/credentials      2 secrets   ([default] aws_access_key_id + aws_secret_access_key)
~/.npmrc                1 secret    (//registry.npmjs.org/:_authToken)
~/.config/gh/hosts.yml  1 secret    (github.com.oauth_token)
```

`scan_config` was pre-seeded so the run skipped the interactive wizard. Each
fixture file got a sha256 manifest snapshot before the run.

## Results

```
=== Running trove --rescan ===
trove: scanned 5 file(s); 11 secret observation(s); 0 error(s)

=== After scan, store schema check ===
schema_compat=kp-v0.9  version=1  secrets=11

=== Checking for secret leakage in global.json ===
no-leak: no full secret value present in store JSON

=== Sample fingerprint shape ===
key=default.aws_access_key_id            id=blake3:a71694…  preview=AKIAIOSF...RE12
key=default.aws_secret_access_key        id=blake3:2b0c68…  preview=fake/fix...+aWS
key=github.com.oauth_token               id=blake3:d24199…  preview=gho_Fake...zzzz
```

### HTTP API

```
GET  /api/secrets                                            200 (11 entries)
POST /api/secrets/{id}/reveal       (×3 from 3 sources)      200 (value-type=string)
POST /api/secrets/{id}/stale                                 204
POST /api/secrets/{id}/rotated                               204
PUT  /api/secrets/{id}/annotation                            204
                                       — persisted: notes, tags, source_url, rotate_url
```

### Drift via SSE

The test (not trove) edited `SHARED_TOKEN` in the fixture `.env`; trove's
fsnotify watcher detected the change and the in-process bus emitted events
to the `/api/events` SSE stream. 13 SSE event lines observed within 5s of
the file edit:

```
event: scan_started
event: secret_refreshed   (×N for each tracked secret as the rescan re-fingerprints)
```

### Source-file mutation audit

```
PASS: only .env mutated by the test; every other fixture file byte-identical.
```

i.e. the only file in the manifest that changed is the one the test itself
mutated. trove read every other fixture file but did not write or modify any
of them.

## Deviation from brief

- The annotation endpoint is `PUT /api/secrets/{id}/annotation` (P5 polecat's
  shape), not the brief's `PATCH /api/secrets/{id}`. The polecat's shape is
  arguably nicer (resource-scoped, idempotent PUT). Not a bug; spec/wording
  drift only.

## Things to do before public ship

1. **Push** — P7 (`8f06a0f`) is merged locally but origin rejects the
   workflow file (`.github/workflows/trove-ci.yml`) because the OAuth token
   used in the polecat campaign lacks the `workflow` scope. Rome's session
   has the right token and should push.
2. **First-run wizard end-to-end** — this dogfood pass pre-seeded
   `scan_config`. The wizard is exercised by P3's unit tests but has not
   been driven by a human in a real terminal yet.
3. **macOS smoke** — only Linux was dogfooded here. The CI matrix in P7
   covers darwin/{amd64,arm64} but a hands-on run is wise.
4. **Naming + landing page** — `trove.so` domain registration + privacy doc
   are still on `rf-s5y` (human-blocked).
5. **rafter-secure-design walk** before any keystore code lands (`rf-4fc`).

## Sign-off

trove v0.1 (commit `8f06a0f`) is functionally complete for the
spec'd v0.1-minus-keystore scope and operates within Rome's ZERO-mutations
hard rule end-to-end. **Verdict: SHIP**, modulo the operational follow-ups above.
