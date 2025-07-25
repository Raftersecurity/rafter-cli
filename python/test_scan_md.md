You are a senior Application-Security, Web-Application, and Cloud-Reliability engineer.
# Security Issues and Vulnerabilities 

**Total Issues:** 3

This report contains 3 security issues found in the repository (full details follow). Each issue requires attention and remediation. Proceed one-by-one and think step-by-step to understand and remediate them.

## Issues Summary
### Issue 1
**Rule ID:** CKV2_GHA_1
**File:** .github/workflows/firebase-hosting-merge.yml
**Line:** 1
**Description:** Ensure top-level permissions are not set to write-all

### Issue 2
**Rule ID:** WEAK_CRYPTO
**File:** src/lib/utils.ts
**Line:** 8
**Description:** Weak crypto usage (md5/sha1) found: // sha1 mistake to fix

### Issue 3
**Rule ID:** CVE-2025-5889
**File:** package-lock.json
**Line:** 2572
**Description:** Package: brace-expansion
Installed Version: 2.0.1
Vulnerability CVE-2025-5889
Severity: LOW
Fixed Version: 2.0.2, 1.1.12, 3.0.1, 4.0.1
Link: [CVE-2025-5889](https://avd.aquasec.com/nvd/cve-2025-5889)

Please analyze these 3 security vulnerabilities and provide:
1. A comprehensive analysis of the security risks
2. Prioritized remediation steps
3. Code examples for fixes
4. Prevention strategies for future development