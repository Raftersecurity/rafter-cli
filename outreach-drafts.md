# Issue-First Outreach Pilot — Draft Disclosures

**Status**: DRAFT — DO NOT POST until founder approval
**Date**: 2026-03-27
**Bead**: rc-yha

---

## Candidate 1: Keerthib-512/learn_notes

**Repo**: https://github.com/Keerthib-512/learn_notes
**Stars**: 0 | **Last push**: Oct 2025 | **File**: `backend/.env.bak`
**Exposed credentials**:
- OpenAI API key (`sk-proj-fz6z...cMMA`) — live, billable
- Supabase service role key (full admin access to Supabase project)
- SendGrid API key (`SG._uDez...YT8`) — can send email as the project
- JWT signing secret

### Draft Issue Title

> Security: API keys and database credentials exposed in committed `.env.bak`

### Draft Issue Body

```markdown
Hi there — I'm a developer who works on security tooling, and I wanted to flag
something I noticed while scanning for exposed credentials on GitHub.

**The file `backend/.env.bak` contains what appear to be live API keys:**

- An OpenAI API key (`sk-proj-...`) — this is billable and could be used to
  run up charges on your account
- A Supabase service role key — this grants full admin access to your Supabase
  project (bypasses RLS)
- A SendGrid API key — can be used to send email from your domain
- A JWT signing secret — could be used to forge authentication tokens

**Recommended immediate steps:**

1. **Rotate all keys now** — revoke the OpenAI key at
   https://platform.openai.com/api-keys, regenerate the Supabase service key,
   and regenerate the SendGrid key
2. **Remove the file from Git history** — deleting the file from `main` isn't
   enough since the keys remain in commit history. Use `git filter-repo` or
   BFG Repo Cleaner to scrub them
3. **Add `.env*` to your `.gitignore`** to prevent this in the future

**Prevention tools you might find useful:**

- [gitleaks](https://github.com/gitleaks/gitleaks) — pre-commit hook that
  catches secrets before they're pushed
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — scans Git
  history for high-entropy strings and known key patterns
- [rafter](https://github.com/raftercli/rafter) — security CLI that
  integrates with AI coding agents to catch secrets, risky commands, and
  policy violations in real time

No judgment — this happens to everyone. Just wanted to make sure you knew
before anyone with bad intentions found it.

Best of luck with IntelliNotes! 🛡️
```

---

## Candidate 2: patriotnewsactivism/buildmybot2

**Repo**: https://github.com/patriotnewsactivism/buildmybot2
**Stars**: 1 | **Last push**: Mar 2026 (active!) | **File**: `.env.txt`
**Exposed credentials**:
- Supabase project URL + anon key
- PostgreSQL direct connection string with password (`BuildMyBot123!`)
- Database username and password in plaintext

### Draft Issue Title

> Security: Database credentials exposed in `.env.txt`

### Draft Issue Body

```markdown
Hi — heads up on a security issue I spotted. The file `.env.txt` in your repo
contains what appear to be live database credentials:

- A PostgreSQL connection string with the password in plaintext
  (`DATABASE_URL=postgresql://postgres...:BuildMyBot123!@...`)
- Supabase project URL and anon key
- `PGPASSWORD` set explicitly

**This means anyone can connect directly to your production database.**

**Recommended immediate steps:**

1. **Change your database password immediately** in the Supabase dashboard
   (Settings → Database)
2. **Regenerate your Supabase anon key** if you use RLS policies that depend
   on it
3. **Remove `.env.txt` from Git history** using `git filter-repo` or
   BFG Repo Cleaner — just deleting the file leaves credentials in commit
   history
4. **Add `*.env*` to `.gitignore`**

**Tools to prevent this going forward:**

- [gitleaks](https://github.com/gitleaks/gitleaks) — pre-commit secret
  scanning
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — Git history
  scanner
- [rafter](https://github.com/raftercli/rafter) — security CLI for AI coding
  agents with built-in secret scanning and policy enforcement

This is super common — especially when `.env` variants like `.env.txt` bypass
standard `.gitignore` rules. Just wanted to flag it before anyone else notices.

Good luck with BuildMyBot! 🛡️
```

---

## Candidate 3: serebano/tictapp-storage-api

**Repo**: https://github.com/serebano/tictapp-storage-api
**Stars**: 0 | **Last push**: Oct 2022 | **File**: `.env.2`
**Exposed credentials**:
- Supabase anon key and service role key (JWTs)
- PostgreSQL connection string with password
- Cloudflare R2 access key and secret key
- JWT signing secret (`PGRST_JWT_SECRET`)

### Draft Issue Title

> Security: Multiple API keys and database credentials exposed in `.env.2`

### Draft Issue Body

```markdown
Hi — I wanted to flag a credential exposure I found in this repo. The file
`.env.2` contains several sets of live-looking credentials:

- **Cloudflare R2 keys** (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) —
  grants access to your object storage
- **PostgreSQL connection string** with password — direct database access
- **Supabase service role key** — bypasses Row Level Security
- **JWT signing secret** — could be used to forge authentication tokens

Even though this repo may no longer be actively maintained, **these
credentials may still be valid** and could be used to access your
infrastructure.

**Recommended steps:**

1. **Rotate all credentials** — Cloudflare R2 keys (Cloudflare dashboard →
   R2 → API Tokens), Supabase keys, and database password
2. **Scrub from Git history** with `git filter-repo` or BFG Repo Cleaner
3. **Add `.env*` to `.gitignore`**

**Scanning tools that catch this before it ships:**

- [gitleaks](https://github.com/gitleaks/gitleaks) — pre-commit secret detection
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — deep Git
  history scanning
- [rafter](https://github.com/raftercli/rafter) — security toolkit for
  developers using AI coding agents

Hope this helps — just trying to make sure exposed keys get rotated. 🛡️
```

---

## Candidate 4: saber13812002/trello-clone-laravel-8-open-source

**Repo**: https://github.com/saber13812002/trello-clone-laravel-8-open-source
**Stars**: 12 | **Last push**: Mar 2023 | **File**: `.env-`
**Exposed credentials**:
- Remote MySQL root credentials (host: `s11.liara.ir`, password: `mOuOTJJCc7eoQf8b24TYcigO`)
- Laravel APP_KEY (used for encryption)

### Draft Issue Title

> Security: Database root credentials exposed in `.env-`

### Draft Issue Body

```markdown
Hi — security heads-up for this project. The file `.env-` contains what
appear to be live remote database credentials:

- **MySQL root password** for `s11.liara.ir:34612` — this is a remote host,
  meaning the credentials are potentially usable from anywhere
- **Laravel APP_KEY** — used to encrypt session data and other sensitive
  values

Since this is a root-level database account on a remote host, the exposure
is high-severity.

**Recommended immediate steps:**

1. **Change the MySQL password immediately** in your Liara dashboard
2. **Rotate the Laravel APP_KEY** (`php artisan key:generate`) — note this
   will invalidate existing encrypted data
3. **Remove the file from Git history** — `git filter-repo` or BFG Repo
   Cleaner
4. **Restrict MySQL network access** to only your application's IP if
   possible

**Prevention tools:**

- [gitleaks](https://github.com/gitleaks/gitleaks) — pre-commit hooks for
  secret detection
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — scans Git
  history
- [rafter](https://github.com/raftercli/rafter) — security CLI with
  built-in secret scanning and AI agent policy enforcement

This is a common issue with `.env` file variants — `.env-` bypasses the
usual `.gitignore` entry for `.env`. Adding `*.env*` (with wildcards) to
`.gitignore` would catch these variants.

Great project by the way — just wanted to make sure the credentials get
rotated. 🛡️
```

---

## Candidate 5: uloydev/designin

**Repo**: https://github.com/uloydev/designin
**Stars**: 2 | **Last push**: Jan 2023 | **File**: `.env.save.1`
**Exposed credentials**:
- AWS RDS hostname + credentials (`dbdesignin.ccwqeyfzdvo6.ap-southeast-1.rds.amazonaws.com`, admin/asdqwe32)
- Gmail SMTP credentials

### Draft Issue Title

> Security: AWS RDS credentials and email password exposed in `.env.save.1`

### Draft Issue Body

```markdown
Hi — I wanted to let you know about a credential exposure in this repo.
The file `.env.save.1` contains:

- **AWS RDS database credentials** — hostname
  `dbdesignin.ccwqeyfzdvo6.ap-southeast-1.rds.amazonaws.com` with
  username `admin` and password in plaintext
- **Gmail SMTP password** — could be used to send email from your account

Even if the RDS instance has been shut down, the password pattern may be
reused elsewhere.

**Recommended steps:**

1. **Change the RDS password** (if the instance still exists) via AWS
   Console or `aws rds modify-db-instance`
2. **Change the Gmail password** and enable 2FA if not already set
3. **Remove from Git history** using `git filter-repo` or BFG Repo Cleaner
4. **Add `.env*` to `.gitignore`** — `.env.save.1` isn't caught by a
   simple `.env` gitignore entry

**Tools to prevent this:**

- [gitleaks](https://github.com/gitleaks/gitleaks) — catches secrets in
  pre-commit hooks
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — scans full
  Git history
- [rafter](https://github.com/raftercli/rafter) — security CLI for
  developers and AI coding agents

Hope this helps — just flagging it so you can rotate the credentials. 🛡️
```

---

## Outreach Notes

**Tone**: Helpful, non-judgmental, specific. Each issue names the exact file,
the exact risk, and gives actionable remediation steps. Rafter is mentioned
alongside gitleaks and trufflehog as one of three options — not as a hard sell.

**Risk mitigation**:
- All issues are genuine security disclosures with real value to the maintainer
- Rafter is mentioned in a list with established tools, not promoted aggressively
- Each issue includes specific rotation instructions, not just "you have a leak"
- Tone is peer-to-peer, not corporate marketing

**Posting order** (suggested):
1. Start with Candidate 1 or 2 (most recent activity, most likely to respond)
2. Wait for response before posting others
3. One negative signal = pause entire program per handoff instructions
