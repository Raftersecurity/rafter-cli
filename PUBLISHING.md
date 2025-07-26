# Publishing Guide

Below is a **hands-on checklist** for publishing **@rafter-security/cli** (Node) and **rafter-cli** (Python) *from your laptop*—no CI involved.
Follow it top-to-bottom and you'll go from fresh clone ➜ globally installable packages on npm & PyPI in ~10 minutes.

---

## 0. One-time workstation prep (do once per machine)

### 0-A · Install required CLIs

```bash
# Node toolchain
corepack enable       # ships with Node ≥16; provides pnpm & yarn
corepack prepare pnpm@9 --activate

# Python packaging tools
python -m pip install --upgrade build twine
```

### 0-B · Log in to registries

* **npm**

  ```bash
  npm login               # enter username/password/OTP once
  ```

  `~/.npmrc` now contains an authToken.

* **PyPI**

  ```bash
  python -m twine upload -r pypi --username __token__ --password pypi-XXXXXXXXXXXXXXXX --skip-existing dummy.file
  ```

  – Twine stores the token in `~/.pypirc`.
  *(Upload will fail for the dummy file—that's fine; the login sticks.)*

---

## 1. Check versions & bump

```bash
# Node
sed -n '5,10p' node/package.json      # confirm "version": "0.2.0" etc.

# Python
grep -A3 "project.name" python/pyproject.toml
```

If you need to bump:

```bash
npm version minor           # bumps Node + creates a Git tag (optional)
# then manually edit python/pyproject.toml to the same 0.3.0
```

Commit the change:

```bash
git commit -am "release: 0.3.0"
```

---

## 2. Build artifacts

### 2-A · Node tarball

```bash
pnpm install --frozen-lockfile          # makes sure you're up to date
pnpm run build                          # emits dist/index.js or similar
npm pack                                # creates ./rafter-cli-0.3.0.tgz
```

### 2-B · Python wheel & sdist

```bash
cd python
python -m build                         # dist/rafter_cli-0.3.0-*.whl & .tar.gz
cd ..
```

*(Inspect the tarball/wheel if curious—always good to sanity-check.)*

---

## 3. Smoke-test locally (optional but recommended)

```bash
# Node – install the tarball in a throw-away dir
mkdir tmp-rafter-npmtmp && cd $_
npm i -g ../rafter-cli-0.1.0.tgz
rafter --version
cd -

# Python – install wheel into a venv
python -m venv /tmp/rafter-venv && source /tmp/rafter-venv/bin/activate
pip install python/dist/rafter_cli-0.3.0-py3-none-any.whl
rafter --version
deactivate
```

If both commands print `0.3.0`, you're good.

---

## 4. Publish for real

### 4-A · npm registry

```bash
# From repo root
npm publish node/ --access public

# OR from the node directory
cd node && npm publish --access public
```

*Gotcha*: if you re-publish the same version you'll see **"EPUBLISHCONFLICT"**—bump the version or add `--force` (not advised).

### 4-B · PyPI registry

```bash
cd python
python -m twine upload dist/*          # uploads both wheel & sdist
cd ..
```

> **Tip** – To dry-run first, swap `pypi` for `testpypi`:
> `python -m twine upload -r testpypi dist/*`

---

## 5. Verify from fresh environment

```bash
# Node (npm, pnpm, yarn all hit the same registry)
docker run --rm node:20-alpine sh -c "npm i -g @rafter-security/cli@0.3.0 && rafter --version"

# Python
docker run --rm python:3.11-alpine sh -c "pip install rafter-cli==0.3.0 && rafter --version"
```

Both should echo `0.3.0`.

---

## 6. Tag + push (if you didn't earlier)

```bash
git tag v0.3.0
git push && git push --tags
```

---

## 7. Post-release housekeeping

1. **CHANGELOG.md** – append a header for 0.3.0 and note major tweaks.
2. **README badges** – update version badge if you use one.
3. **Announce** in Slack/Twitter/Changelog.

---

### Troubleshooting quick table

| Symptom                                 | Likely cause                             | Fix                                                                                  |
| --------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------ |
| `E403 You must be logged in to publish` | npm token expired or scoped wrong        | `npm login` again or regenerate "Automation" token                                   |
| `HTTPError 403` from Twine              | Wrong PyPI token or project name taken   | Check `~/.pypirc`; maybe claim the project first via web UI                          |
| CLI installs but command not found      | `bin` / `console_scripts` mis-configured | Ensure `package.json > bin` & `pyproject.toml > project.scripts` point to executable |
| Version already exists                  | You forgot to bump before publishing     | `npm unpublish --force` *within 72 h* (careful!) or release `0.3.1`                  |

---

## Recap

1. **Log in** once (`npm login`, `twine` with token).
2. **Bump** versions → commit.
3. **Build** (`pnpm run build`, `python -m build`).
4. **`npm publish`** + **`twine upload`**.
5. **Verify** installs.
   Done—you've manually shipped the latest Rafter CLI to the world. 🎉 