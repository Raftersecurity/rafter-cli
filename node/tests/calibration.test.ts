/**
 * Calibration harness for prompt-shield (rc-6fg).
 *
 * Three independent assertion blocks run against shared corpora and a
 * per-pattern matrix:
 *
 *   1. Negative corpus — `shared-docs/calibration/negative.txt`
 *      Every non-comment line is a prompt that MUST produce zero detections.
 *      The current FP count is recorded as KNOWN_FP_FLOOR; the test fails
 *      if it grows. Lower the floor as patterns improve.
 *
 *   2. Positive corpus — `shared-docs/calibration/positive.yaml`
 *      Each case lists the expected secret values; recall must clear
 *      RECALL_FLOOR (currently 0.80, ratchets up).
 *
 *   3. Per-pattern matrix (defined here, not in the YAML — provider tokens
 *      would trip rafter's own pretool hook + GitHub push protection).
 *      For each of the 24 patterns: at least one positive case fires that
 *      pattern, and at least one near-miss case does NOT.
 *
 * Provider-token literals are split at module load (e.g. `"sk_" + "live_"`)
 * so the source file itself does not contain a complete pattern match —
 * only the joined runtime values do.
 */
import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import yaml from "js-yaml";
import { fileURLToPath } from "url";
import { detectSecrets, DetectedSecret } from "../src/core/prompt-shield.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.resolve(__dirname, "../../shared-docs/calibration");

// Tunable floors. The intent (per rc-6fg) is to ratchet UP recall + precision
// and DOWN the FP count. Loosening any floor requires a bead reference here.
// Today's 6 known FPs all fire on `Inline credential assignment` where the
// LHS contains a credential keyword (api_key, secret, token, …) but the RHS
// is a non-secret identifier (X-Api-Key, ordered_set, aws-default, public,
// opaque, argon2id). Fix tracked in rc-wk5.
const KNOWN_FP_FLOOR = 6; // negative corpus: lines that produce ≥1 detection
const RECALL_FLOOR = 0.8; // positive corpus: fraction of expected values found
const PRECISION_FLOOR = 0.75; // combined: tp / (tp + fp); target 0.95

// ──────────── Token construction (split to dodge file scanners) ────────────
const AKIA = "AKI" + "A";
const SK_LIVE = "sk_" + "live_";
const RK_LIVE = "rk_" + "live_";
const GHP = "ghp" + "_";
const GHO = "gho" + "_";
const GHU = "ghu" + "_";
const GHR = "ghr" + "_";
const SLACK_BOT = "xox" + "b-";
const NPM_PREFIX = "npm" + "_";
const PYPI_PREFIX = "pypi-AgEI" + "cHlwaS5vcmc";
const AIZA = "AI" + "za";
const AWS_KEYWORD = "aw" + "s"; // lowercase for inline use; const names use AW + S to dodge file scan
const AWS_DOCS_KEY = AKIA + "IOSFODNN7EXAMPLE"; // 20-char AWS docs example
const AWS_SECRET_TAIL = "wJalrXUtnFEMI/K7MDE" + "NG/bPxRfiCYEXAMPLEKEY"; // 40 chars combined
const PG_SCHEME = "post" + "gres";
const MYSQL_SCHEME = "my" + "sql";
const MONGO_SCHEME = "mong" + "odb";
const PRIV_KEY_HEADER = "-----BEGI" + "N RSA PRIVATE KEY-----";
const APIKEY_KW = "api" + "_key";
const SECRET_KW = "sec" + "ret";
const BEARER_KW = "Bear" + "er";

const ALNUM36 = "abcdefghijklmnopqrstuvwxyz0123456789";
const ALNUM24 = "abcdefghijklmnopqrstuvwx";
const ALNUM32 = "abcdefghijklmnopqrstuvwxyz012345";
const ALNUM35 = "abcdefghijklmnopqrstuvwxyz012345678";
const ALNUM50 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN";
// 76 chars: ALNUM50 + 26 extra. Built rather than literal so length is obvious.
const ALNUM76 = (ALNUM50 + "OPQRSTUVWXabcdefghijklmnop").slice(0, 76);
const HEX32 = "0123456789abcdef0123456789abcdef";

// JWT chunks — split so no pattern fires in source
const JWT_HEADER = "eyJ" + "hbGciOiJIUzI1NiJ9";
const JWT_PAYLOAD = "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0";
const JWT_SIG = "abcdefghijklmnopqrstuvwxyz012345ABCDEFGHIJ";

// Sanity-check token lengths — prevents silent drift if someone tweaks above.
for (const [k, v, n] of [
  ["ALNUM76", ALNUM76, 76],
  ["ALNUM50", ALNUM50, 50],
  ["ALNUM35", ALNUM35, 35],
  ["ALNUM36", ALNUM36, 36],
  ["ALNUM32", ALNUM32, 32],
  ["ALNUM24", ALNUM24, 24],
  ["HEX32", HEX32, 32],
  ["AWS_SECRET_TAIL", AWS_SECRET_TAIL, 40],
] as const) {
  if (v.length !== n) throw new Error(`${k} length mismatch: ${v.length}, expected ${n}`);
}

// ─────────────────────── Per-pattern hit/miss matrix ───────────────────────
type PatternCase = {
  name: string;
  hits: { prompt: string; value: string }[];
  misses: string[];
};

const MATRIX: PatternCase[] = [
  {
    name: "AWS Access Key ID",
    hits: [{ prompt: `use ${AWS_DOCS_KEY} for the test`, value: AWS_DOCS_KEY }],
    misses: [`the ${AKIA} prefix is part of AWS keys`, `${AKIA}SHORT123`],
  },
  {
    name: "AWS Secret Access Key",
    hits: [
      // Full match includes `aws...` prefix per the regex shape, not just the tail.
      {
        prompt: `${AWS_KEYWORD}_secret = ${AWS_SECRET_TAIL} now`,
        value: `${AWS_KEYWORD}_secret = ${AWS_SECRET_TAIL}`,
      },
    ],
    misses: [`${AWS_KEYWORD} is a cloud provider`],
  },
  {
    name: "GitHub Personal Access Token",
    hits: [{ prompt: `auth with ${GHP}${ALNUM36} now`, value: `${GHP}${ALNUM36}` }],
    misses: [`${GHP}tooshort`, `gh prefix is for github`],
  },
  {
    name: "GitHub OAuth Token",
    hits: [{ prompt: `oauth: ${GHO}${ALNUM36} returned`, value: `${GHO}${ALNUM36}` }],
    misses: [`${GHO}short`],
  },
  {
    name: "GitHub App Token",
    hits: [{ prompt: `app: ${GHU}${ALNUM36} ok`, value: `${GHU}${ALNUM36}` }],
    misses: [`${GHU}toosmall`],
  },
  {
    name: "GitHub Refresh Token",
    hits: [{ prompt: `refresh: ${GHR}${ALNUM76} ok`, value: `${GHR}${ALNUM76}` }],
    misses: [`${GHR}${ALNUM36}`],
  },
  {
    name: "Google API Key",
    hits: [{ prompt: `google api: ${AIZA}${ALNUM35} now`, value: `${AIZA}${ALNUM35}` }],
    misses: [`${AIZA}short`],
  },
  {
    name: "Google OAuth",
    hits: [
      {
        prompt: `client id 1234567890-${ALNUM32}.apps.googleusercontent.com is ours`,
        value: `1234567890-${ALNUM32}.apps.googleusercontent.com`,
      },
    ],
    misses: [`apps.googleusercontent.com is the host`],
  },
  {
    name: "Slack Token",
    hits: [
      { prompt: `slack: ${SLACK_BOT}${ALNUM24} success`, value: `${SLACK_BOT}${ALNUM24}` },
    ],
    misses: [`${SLACK_BOT}short`],
  },
  {
    name: "Slack Webhook",
    hits: [
      {
        prompt: `webhook https://hooks.slack.com/services/T01234567/B01234567/${ALNUM24} ok`,
        value: `https://hooks.slack.com/services/T01234567/B01234567/${ALNUM24}`,
      },
    ],
    misses: [`hooks.slack.com is the slack webhook host`],
  },
  {
    name: "Stripe API Key",
    hits: [{ prompt: `stripe: ${SK_LIVE}${ALNUM24} ok`, value: `${SK_LIVE}${ALNUM24}` }],
    misses: [`${SK_LIVE}short`],
  },
  {
    name: "Stripe Restricted API Key",
    hits: [
      {
        prompt: `stripe restricted: ${RK_LIVE}${ALNUM24} ok`,
        value: `${RK_LIVE}${ALNUM24}`,
      },
    ],
    misses: [`${RK_LIVE}short`],
  },
  {
    name: "Twilio API Key",
    hits: [{ prompt: `twilio: SK${HEX32} ok`, value: `SK${HEX32}` }],
    misses: [`SK is a Twilio prefix`, `SKshort`],
  },
  {
    name: "Generic API Key",
    hits: [
      // The Generic API Key regex captures the whole `api_key="..."` form.
      // Inline credential assignment also fires on the inner value — the
      // matrix only asserts that THIS pattern fires with its full match.
      {
        prompt: `config ${APIKEY_KW}="abcd1234efgh5678" loaded`,
        value: `${APIKEY_KW}="abcd1234efgh5678"`,
      },
    ],
    misses: [
      `the ${APIKEY_KW} is short`,
      `${APIKEY_KW}="abc"`,
      `${APIKEY_KW}="abcdefghijklmnop"`, // no digit
    ],
  },
  {
    name: "Generic Secret",
    hits: [
      {
        prompt: `cfg ${SECRET_KW}="abcd1234efghIJKL" loaded`,
        value: `${SECRET_KW}="abcd1234efghIJKL"`,
      },
    ],
    misses: [`${SECRET_KW} = unquoted_value`, `${SECRET_KW}="short1"`],
  },
  {
    name: "Private Key",
    hits: [{ prompt: `paste:\n${PRIV_KEY_HEADER}\nMIIEowIBA`, value: PRIV_KEY_HEADER }],
    misses: [`BEGIN PRIVATE block`, `the private key file is rotated weekly`],
  },
  {
    name: "Bearer Token",
    hits: [
      {
        prompt: `Authorization: ${BEARER_KW} ${ALNUM32}aaaa1234`,
        value: `${BEARER_KW} ${ALNUM32}aaaa1234`,
      },
    ],
    misses: [`the ${BEARER_KW.toLowerCase()} token is missing`, `${BEARER_KW} short`],
  },
  {
    name: "Database Connection String",
    hits: [
      {
        prompt: `connect to ${PG_SCHEME}://user:correctsecret@host:5432/db now`,
        value: `${PG_SCHEME}://user:correctsecret@host:5432/db`,
      },
    ],
    misses: [
      `the ${PG_SCHEME} database is on host primary`,
      `${PG_SCHEME}://host:5432/db`, // no creds
    ],
  },
  {
    name: "JSON Web Token",
    hits: [
      {
        prompt: `the jwt is ${JWT_HEADER}.${JWT_PAYLOAD}.${JWT_SIG} signed`,
        value: `${JWT_HEADER}.${JWT_PAYLOAD}.${JWT_SIG}`,
      },
    ],
    misses: [`eyJ is the json header prefix`],
  },
  {
    name: "npm Access Token",
    hits: [
      { prompt: `npm publish with ${NPM_PREFIX}${ALNUM36} success`, value: `${NPM_PREFIX}${ALNUM36}` },
    ],
    misses: [`${NPM_PREFIX}short`],
  },
  {
    name: "PyPI Token",
    hits: [{ prompt: `pypi: ${PYPI_PREFIX}${ALNUM50} ok`, value: `${PYPI_PREFIX}${ALNUM50}` }],
    misses: [`${PYPI_PREFIX}short`],
  },
  {
    name: "Inline credential assignment",
    hits: [{ prompt: `DB_PASSWORD=hunter2andmore set`, value: `hunter2andmore` }],
    misses: [
      `secret_id=12345`,
      `DB_NAME=production`,
    ],
  },
  {
    name: "Inline credential phrase",
    hits: [{ prompt: `the password is hunter2andmore now`, value: `hunter2andmore` }],
    misses: [
      `the password to victory is patience`,
      `set api_key environment variable`,
    ],
  },
  {
    name: "URL with credentials",
    hits: [
      {
        prompt: `fetch https://api-user:correctsecret@api.example.com/v1/me ok`,
        value: `correctsecret`,
      },
    ],
    misses: [
      `https://api.example.com/v1/me`,
      `git@github.com:org/repo.git`,
    ],
  },
];

// ───────────────────────────── Loaders ─────────────────────────────────────
function loadNegatives(): string[] {
  const text = fs.readFileSync(path.join(FIXTURES, "negative.txt"), "utf-8");
  return text
    .split(/\r?\n/)
    .map((l) => l.replace(/\s+$/, ""))
    .filter((l) => l.trim() && !l.trim().startsWith("#"));
}

interface PositiveCase {
  id: string;
  prompt: string;
  expects: { value: string; pattern?: string }[];
}

function loadPositives(): PositiveCase[] {
  const text = fs.readFileSync(path.join(FIXTURES, "positive.yaml"), "utf-8");
  const parsed = yaml.load(text) as { cases: PositiveCase[] };
  return parsed.cases;
}

function describeDetections(d: DetectedSecret[]): string {
  return d.map((x) => `${x.patternName}:${JSON.stringify(x.value)}`).join(", ") || "<none>";
}

// ───────────────────────────── Test cases ──────────────────────────────────
describe("calibration: negative corpus (must produce no detections)", () => {
  it(`stays at or below KNOWN_FP_FLOOR=${KNOWN_FP_FLOOR}`, () => {
    const negatives = loadNegatives();
    const fps: { prompt: string; hits: DetectedSecret[] }[] = [];
    for (const prompt of negatives) {
      const detected = detectSecrets(prompt);
      if (detected.length > 0) fps.push({ prompt, hits: detected });
    }
    if (fps.length > KNOWN_FP_FLOOR) {
      const lines = fps.map(
        (fp) => `  ${JSON.stringify(fp.prompt)} -> ${describeDetections(fp.hits)}`
      );
      console.error(
        `\nFalse positives in negative corpus (${fps.length}, floor=${KNOWN_FP_FLOOR}):\n${lines.join("\n")}\n`
      );
    }
    expect(fps.length).toBeLessThanOrEqual(KNOWN_FP_FLOOR);
  });
});

describe("calibration: positive corpus (must detect known secrets)", () => {
  it(`recall >= ${(RECALL_FLOOR * 100).toFixed(0)}%`, () => {
    const positives = loadPositives();
    let totalExpected = 0;
    let found = 0;
    const missed: string[] = [];
    for (const c of positives) {
      const detected = detectSecrets(c.prompt);
      const detectedValues = new Set(detected.map((d) => d.value));
      const detectedPairs = new Set(detected.map((d) => `${d.patternName}\x00${d.value}`));
      for (const exp of c.expects) {
        totalExpected++;
        const valueOk = detectedValues.has(exp.value);
        const patternOk = !exp.pattern || detectedPairs.has(`${exp.pattern}\x00${exp.value}`);
        if (valueOk && patternOk) {
          found++;
        } else {
          missed.push(
            `[${c.id}] expected ${exp.pattern ? exp.pattern + ":" : ""}${JSON.stringify(exp.value)} | detected: ${describeDetections(detected)}`
          );
        }
      }
    }
    const recall = totalExpected > 0 ? found / totalExpected : 1;
    if (missed.length > 0) {
      console.error(
        `\nPositive recall ${(recall * 100).toFixed(1)}% (${found}/${totalExpected}). Missed:\n  ${missed.join("\n  ")}`
      );
    }
    expect(recall).toBeGreaterThanOrEqual(RECALL_FLOOR);
  });
});

describe("calibration: combined precision", () => {
  it(`precision >= ${(PRECISION_FLOOR * 100).toFixed(0)}%`, () => {
    const positives = loadPositives();
    const negatives = loadNegatives();
    let tp = 0;
    let fp = 0;
    for (const c of positives) {
      const detected = detectSecrets(c.prompt);
      const expectedValues = new Set(c.expects.map((e) => e.value));
      for (const d of detected) {
        if (expectedValues.has(d.value)) tp++;
        else fp++;
      }
    }
    for (const prompt of negatives) {
      const detected = detectSecrets(prompt);
      fp += detected.length;
    }
    const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
    if (precision < PRECISION_FLOOR) {
      console.error(`\nPrecision ${(precision * 100).toFixed(1)}% (tp=${tp}, fp=${fp})`);
    }
    expect(precision).toBeGreaterThanOrEqual(PRECISION_FLOOR);
  });
});

describe("calibration: per-pattern hit/miss matrix", () => {
  for (const entry of MATRIX) {
    describe(entry.name, () => {
      for (const hit of entry.hits) {
        it(`hit: detects in ${JSON.stringify(hit.prompt.slice(0, 60))}…`, () => {
          const detected = detectSecrets(hit.prompt);
          const ok = detected.some(
            (d) => d.patternName === entry.name && d.value === hit.value
          );
          if (!ok) {
            console.error(
              `\n[${entry.name}] expected ${entry.name}:${JSON.stringify(hit.value)}, got ${describeDetections(detected)}`
            );
          }
          expect(ok).toBe(true);
        });
      }
      for (const miss of entry.misses) {
        it(`miss: does NOT fire on ${JSON.stringify(miss.slice(0, 60))}…`, () => {
          const detected = detectSecrets(miss);
          const matched = detected.some((d) => d.patternName === entry.name);
          if (matched) {
            console.error(
              `\n[${entry.name}] unexpectedly fired on ${JSON.stringify(miss)}: ${describeDetections(detected)}`
            );
          }
          expect(matched).toBe(false);
        });
      }
    });
  }
});
