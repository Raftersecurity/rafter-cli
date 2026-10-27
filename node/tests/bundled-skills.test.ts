import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";

// A skill that declares `allowed-tools` needs a permission approval before it
// loads. Non-interactive sessions (CI, SDK, `claude -p`) cannot give one, so the
// skill returns only its description. Rafter's bundled skills must not declare it.
const SKILLS_DIR = path.resolve(__dirname, "../resources/skills");

describe("bundled skills", () => {
  const skills = fs.readdirSync(SKILLS_DIR).filter((d) => fs.existsSync(path.join(SKILLS_DIR, d, "SKILL.md")));

  it.each(skills)("%s loads without an approval (no allowed-tools)", (name) => {
    const text = fs.readFileSync(path.join(SKILLS_DIR, name, "SKILL.md"), "utf-8");
    const frontmatter = text.split(/^---$/m)[1] ?? "";
    expect(frontmatter).toMatch(/^name: /m);
    expect(frontmatter).toMatch(/^description: /m);
    expect(frontmatter).not.toMatch(/^allowed-tools:/m);
  });

  it("finds the skills it checks", () => {
    expect(skills.length).toBeGreaterThanOrEqual(4);
  });
});
