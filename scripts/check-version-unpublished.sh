#!/usr/bin/env bash
# Fail the release if this version is ALREADY on the registry.
#
# validate-release checks that node, python and the ClawHub manifests AGREE.
# It never checked whether the agreed version had already shipped -- so when
# main's version equalled the published one, validation passed and the publish
# job failed later, at the registry, with an error that does not say "you forgot
# the bump". That happened THREE times (rf-bcv4 and twice more), each time
# leaving a security fix merged to a public repo and absent from the package
# anyone installs.
#
# FAILS CLOSED. If a registry cannot be reached we exit non-zero, deliberately.
# A release gate that opens because it could not see is the failure we are
# fixing wearing a different hat: the whole point is to stop a release that
# would not publish, and "I do not know" is not "it is fine".
#
# Usage: check-version-unpublished.sh <version> [npm-package] [pypi-package]
set -uo pipefail

VERSION="${1:?usage: $0 <version> [npm-pkg] [pypi-pkg]}"
NPM_PKG="${2:-@rafter-security/cli}"
PYPI_PKG="${3:-rafter-cli}"
rc=0

# --- npm -------------------------------------------------------------------
npm_out=$(npm view "${NPM_PKG}@${VERSION}" version 2>&1)
npm_rc=$?
if [ "$npm_rc" -eq 0 ] && [ "$(printf '%s' "$npm_out" | tr -d '[:space:]')" = "$VERSION" ]; then
  echo "FAIL: npm already serves ${NPM_PKG}@${VERSION} — bump before releasing."
  rc=1
elif printf '%s' "$npm_out" | grep -qiE "E404|not found|is not in this registry"; then
  echo "ok: ${NPM_PKG}@${VERSION} is not published"
else
  echo "FAIL (closed): could not determine whether ${NPM_PKG}@${VERSION} is published."
  echo "  npm exit=${npm_rc}; output: ${npm_out}"
  echo "  Refusing to pass on an unknown. Re-run when the registry is reachable."
  rc=1
fi

# --- PyPI ------------------------------------------------------------------
# PYPI_BASE is overridable so the fail-closed path can be TESTED by pointing it
# at a dead host. An untested fail-closed branch is exactly the kind of check
# that turns out to fail OPEN the one time it matters.
PYPI_BASE="${PYPI_BASE:-https://pypi.org}"
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 \
       "${PYPI_BASE}/pypi/${PYPI_PKG}/${VERSION}/json" 2>/dev/null)
curl_rc=$?
if [ "$curl_rc" -ne 0 ]; then
  echo "FAIL (closed): PyPI unreachable for ${PYPI_PKG} ${VERSION} (curl exit ${curl_rc})."
  rc=1
elif [ "$code" = "200" ]; then
  echo "FAIL: PyPI already serves ${PYPI_PKG} ${VERSION} — bump before releasing."
  rc=1
elif [ "$code" = "404" ]; then
  echo "ok: ${PYPI_PKG} ${VERSION} is not published"
else
  echo "FAIL (closed): unexpected PyPI status ${code} for ${PYPI_PKG} ${VERSION}."
  echo "  Refusing to pass on an unknown."
  rc=1
fi

exit "$rc"
