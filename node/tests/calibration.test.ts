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
 *      RECALL_FLOOR. Pinned just below today's actual; ratchets up.
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
import { spawnSync } from "child_process";
import yaml from "js-yaml";
import { fileURLToPath } from "url";
import { detectSecrets, DetectedSecret, replaceSecretsWithRefs } from "../src/core/prompt-shield.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.resolve(__dirname, "../../shared-docs/calibration");

// Tunable floors. The intent (per rc-6fg) is to ratchet UP recall + precision
// and DOWN the FP count. Loosening any floor requires a bead reference here.
// rc-wk5 closed the 6 prior FPs (kebab-non-secret-rhs class) by gating the
// assignment pattern's RHS through looksLikeIdentifierConfig in
// prompt-shield.ts. Floor now sits at 0.
//
// Floors are pinned just below today's actuals so the suite gates against
// drift. A regex change that drops 2 detections OR adds 1 FP trips the suite.
const KNOWN_FP_FLOOR = 0; // negative corpus: lines that produce ≥1 detection
const RECALL_FLOOR = 0.97; // positive corpus: fraction of expected values found
const PRECISION_FLOOR = 0.95; // combined: tp / (tp + fp); rc-6fg ceiling met

// ──────────── Token construction (split to dodge file scanners) ────────────
const AKIA = "AKI" + "A";
const ASIA = "ASI" + "A"; // session token prefix
const AROA = "ARO" + "A"; // role prefix
const AGPA = "AGP" + "A"; // group prefix
const AIDA = "AID" + "A"; // IAM user prefix
const A3T = "A3" + "T"; // A3T[A-Z0-9] alternation arm — needs +1 char before the 16-char tail
const SK_LIVE = "sk_" + "live_";
const RK_LIVE = "rk_" + "live_";
const GHP = "ghp" + "_";
const GHO = "gho" + "_";
const GHU = "ghu" + "_";
const GHR = "ghr" + "_";
const SLACK_BOT = "xox" + "b-";
const SLACK_USER = "xox" + "p-";  // user token
const SLACK_APP = "xox" + "a-";   // app-level token
const SLACK_REFRESH = "xox" + "r-";
const GHS = "ghs" + "_";           // GitHub Server-to-Server App token
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
    // Regex accepts 9 prefixes; cover one per alternation arm so a
    // refactor that drops any prefix surfaces immediately.
    hits: [
      { prompt: `use ${AWS_DOCS_KEY} for the test`, value: AWS_DOCS_KEY },
      { prompt: `STS issued ${ASIA}IOSFODNN7EXAMPLE for staging`, value: `${ASIA}IOSFODNN7EXAMPLE` },
      { prompt: `assumed role ${AROA}IOSFODNN7EXAMPLE today`, value: `${AROA}IOSFODNN7EXAMPLE` },
      { prompt: `group key ${AGPA}IOSFODNN7EXAMPLE active`, value: `${AGPA}IOSFODNN7EXAMPLE` },
      { prompt: `IAM user ${AIDA}IOSFODNN7EXAMPLE created`, value: `${AIDA}IOSFODNN7EXAMPLE` },
      { prompt: `legacy ${A3T}XIOSFODNN7EXAMPLE found`, value: `${A3T}XIOSFODNN7EXAMPLE` },
    ],
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
    // Regex is `(ghu|ghs)_…`; both prefixes must hit so dropping either
    // half of the alternation surfaces immediately.
    hits: [
      { prompt: `app: ${GHU}${ALNUM36} ok`, value: `${GHU}${ALNUM36}` },
      { prompt: `server-to-server: ${GHS}${ALNUM36} ok`, value: `${GHS}${ALNUM36}` },
    ],
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
    // Regex is `xox[baprs]-…`; cover bot/user/app/refresh so a refactor
    // that narrows the bracket alternation surfaces immediately.
    hits: [
      { prompt: `slack: ${SLACK_BOT}${ALNUM24} success`, value: `${SLACK_BOT}${ALNUM24}` },
      { prompt: `user token ${SLACK_USER}${ALNUM24} ok`, value: `${SLACK_USER}${ALNUM24}` },
      { prompt: `app token ${SLACK_APP}${ALNUM24} ok`, value: `${SLACK_APP}${ALNUM24}` },
      { prompt: `refresh ${SLACK_REFRESH}${ALNUM24} stored`, value: `${SLACK_REFRESH}${ALNUM24}` },
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

// rc-apd #1: round-trip envelope path. detectSecrets() is exercised heavily
// by the corpus + matrix above, but `envBaseName` derivation, longest-first
// substring-safe replacement, and the placeholder filter feed the actual
// hook envelope (additionalContext / llm_request rewrite). A regex change
// that left detection intact while breaking these auxiliary paths would pass
// every other assertion in this file.
describe("calibration: round-trip envelope (rc-apd #1)", () => {
  it("derives envBaseName from the LHS identifier on assignment forms", () => {
    const detected = detectSecrets("Connect with DB_PASSWORD=hunter2andmore please");
    expect(detected).toHaveLength(1);
    expect(detected[0].value).toBe("hunter2andmore");
    expect(detected[0].envBaseName).toBe("DB_PASSWORD");
  });

  it("rewrites the captured value with $ENV_NAME via replaceSecretsWithRefs", () => {
    const prompt = "Connect with DB_PASSWORD=hunter2andmore please";
    const detected = detectSecrets(prompt);
    const valueToName = new Map(detected.map((d) => [d.value, d.envBaseName]));
    const rewritten = replaceSecretsWithRefs(prompt, detected, valueToName);
    expect(rewritten).toBe("Connect with DB_PASSWORD=$DB_PASSWORD please");
  });

  it("longest-first replacement avoids substring shadowing", () => {
    // If the shorter value `hunter2andmore` were replaced first, the
    // substring inside `hunter2andmore_extended` would collide and yield
    // garbage. replaceSecretsWithRefs sorts by value length descending.
    const prompt =
      "DB_PASSWORD=hunter2andmore_extended and AUTH_TOKEN=hunter2andmore here";
    const detected = detectSecrets(prompt);
    const valueToName = new Map(detected.map((d) => [d.value, d.envBaseName]));
    const rewritten = replaceSecretsWithRefs(prompt, detected, valueToName);
    expect(rewritten).toContain("DB_PASSWORD=$DB_PASSWORD");
    expect(rewritten).toContain("AUTH_TOKEN=$AUTH_TOKEN");
    // The shorter value's env-ref must NOT appear inside the longer match.
    expect(rewritten).not.toContain("$AUTH_TOKEN_extended");
  });

  it("URL-with-credentials uses the URL_PASSWORD envBaseName", () => {
    const detected = detectSecrets(
      "connect to redis://admin:hunter2andmore@cache.internal:6379/0"
    );
    const url = detected.find((d) => d.patternName === "URL with credentials");
    expect(url).toBeTruthy();
    expect(url!.envBaseName).toBe("URL_PASSWORD");
  });
});

// rc-apd #2: Node ↔ Python parity. The two implementations are parallel,
// not parity-checked. This test runs detect on the shared corpus through
// both impls and asserts identical (pattern, value) sets per prompt. Drift
// in one impl (e.g. a regex tweaked in Node but not Python) fails here.
//
// Skipped if `python3` isn't on PATH or the Python package isn't importable.
describe("calibration: Node ↔ Python parity (rc-apd #2)", () => {
  it("Python detect_secrets matches Node on every corpus prompt", () => {
    const PYTHON_DIR = path.resolve(__dirname, "../../python");
    const probe = spawnSync(
      "python3",
      ["-c", "import sys; sys.path.insert(0, sys.argv[1]); import rafter_cli.core.prompt_shield", PYTHON_DIR],
      { encoding: "utf-8", timeout: 5000 }
    );
    if (probe.status !== 0) {
      console.warn(`[parity] skipping — python3 / rafter_cli not importable: ${probe.stderr}`);
      return;
    }

    const negatives = loadNegatives();
    const positives = loadPositives().map((c) => c.prompt);
    const prompts = [...negatives, ...positives];

    const nodeResults = prompts.map((p) =>
      detectSecrets(p).map((d) => ({ pattern: d.patternName, value: d.value }))
    );

    const script = [
      "import sys, json",
      `sys.path.insert(0, ${JSON.stringify(PYTHON_DIR)})`,
      "from rafter_cli.core.prompt_shield import detect_secrets",
      "prompts = json.load(sys.stdin)",
      "out = [[{'pattern': d.pattern_name, 'value': d.value} for d in detect_secrets(p)] for p in prompts]",
      "json.dump(out, sys.stdout)",
    ].join("\n");

    const proc = spawnSync("python3", ["-c", script], {
      input: JSON.stringify(prompts),
      encoding: "utf-8",
      timeout: 30000,
      maxBuffer: 10 * 1024 * 1024,
    });
    expect(proc.status, `python detection script failed:\nstderr: ${proc.stderr}`).toBe(0);

    const pythonResults: { pattern: string; value: string }[][] = JSON.parse(proc.stdout);
    expect(pythonResults).toHaveLength(prompts.length);

    const drift: string[] = [];
    for (let i = 0; i < prompts.length; i++) {
      const key = (r: { pattern: string; value: string }) => `${r.pattern}\x00${r.value}`;
      const nodeSet = new Set(nodeResults[i].map(key));
      const pySet = new Set(pythonResults[i].map(key));
      const onlyNode = [...nodeSet].filter((x) => !pySet.has(x));
      const onlyPy = [...pySet].filter((x) => !nodeSet.has(x));
      if (onlyNode.length || onlyPy.length) {
        drift.push(
          `prompt[${i}] ${JSON.stringify(prompts[i].slice(0, 80))}:\n` +
            `    node-only: ${JSON.stringify(onlyNode)}\n` +
            `    python-only: ${JSON.stringify(onlyPy)}`
        );
      }
    }
    if (drift.length > 0) {
      console.error(`\nNode/Python drift on ${drift.length} prompt(s):\n${drift.join("\n")}`);
    }
    expect(drift).toEqual([]);
  });
});
