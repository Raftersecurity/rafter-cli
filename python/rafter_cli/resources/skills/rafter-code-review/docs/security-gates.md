# Security gates: what to check when auditing a codebase

Most exploitable bugs in mature code are not a dangerous sink reached by tainted data. They are a **gate**, a function that decides whether something is allowed, that says yes when it should say no. A one-character change to a comparison, a dropped condition, or a flag that is set and never read is enough. Source-to-sink tracing misses these, because the sink is fine and the data is trusted after the gate.

So in an audit, find the gates first, then try to make each one say yes wrongly.

## 1. Inventory the gates

Grep for the functions that decide, not the ones that act:

- Names: `authorize`, `authenticate`, `allow`, `permit`, `can*`, `is*Allowed`, `has*Permission`, `check*`, `verify*`, `validate*`, `match*`, `isSafe*`, `isTrusted*`, middleware and interceptors.
- Config that feeds them: allowlists, trusted domains or proxies, roles, scopes, ACL rules, TLS and auth settings.
- Callers that skip them: handlers registered without the middleware their siblings use.
- Places no gate name points to: `rafter gates` prints these as **leads** (TLS verification off, a security setting never read, a body read with no limit, prefix or substring matching on a host, URL, path or claim). A lead is a place to look deeper and a question to answer, not a finding; it shares the worklist budget with the gates.

For each gate, write down its contract in one sentence ("only same-origin redirect targets", "only active users with a valid password") before reading the body.

## 2. Ask of every gate: name an input the contract rejects and this code accepts

Work through these failure shapes. Each one has fooled real reviewers.

**Matching that is too loose.**
- Substring, prefix or suffix where equality or a dot-boundary was needed: `strings.Contains(host, allowed)`, `HasSuffix(host, "example.com")` accepting `evilexample.com`, `startswith("/safe")` accepting `/safe-but-not`.
- Case folding or normalization applied on one side only; `EqualFold` where the comparison must be exact.
- Wildcards and globs that match more than intended; an empty pattern or empty list that means "allow all".
- Comparing a truncated value (a prefix of a digest or token) as if it were the whole.

**Decision logic that fails open.**
- The wrong variable checked (a sibling field, the requested resource instead of the actor), or a check applied to some request kinds and skipped for others.
- An early `return nil` or `return true` on an error or missing value; `!= nil` versus `== nil` inverted; `||` where `&&` was needed.
- A default branch, fallback, or "unknown" case that grants access.

**Validity checks that are missing.**
- Authentication that accepts accounts or credentials it should reject (inactive, expired, unverified, revoked); expiry compared with the wrong clock or unit.
- Signatures, MACs or certificates parsed but never verified; key usage, issuer, audience or algorithm not checked.
- TLS or peer verification turned off, or a required check quietly made optional.

**A security value that is set but never read.**
- A flag, field or option the gate computes or accepts (`verified`, `enabled`, `strict`, `requireX`) and then ignores. Grep for each security-relevant field and confirm it is read in the decision, not only assigned.
- A config option parsed and stored but never wired into the code that should honor it.

**A twin that lost its guard.**
- Sibling implementations of the same contract: sync and async variants, two storage or authentication backends, v1 and v2 handlers. Diff them. If one escapes, checks or limits and the other doesn't, the other is the bug.

**Containment and escaping.**
- Paths joined from input without cleaning and re-checking that the result stays under the root, or a symlink followed after the check.
- Filters, queries, HTML or shell built from input without the escaping the neighboring code uses.

**Limits.**
- Size, count, depth or time limits missing, disabled (`-1`, `0` meaning unlimited), or checked after the expensive work.

## 3. Report

For each finding: the file and line of the faulty expression, the contract it breaks, a concrete input that gets through, and what an attacker gains. A gate that holds is not a finding; move on.
