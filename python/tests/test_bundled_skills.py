"""A skill that declares `allowed-tools` needs a permission approval before it
loads. Non-interactive sessions (CI, SDK, `claude -p`) cannot give one, so the
skill returns only its description. Rafter's bundled skills must not declare it."""
import re
from pathlib import Path

import pytest

SKILLS_DIR = Path(__file__).resolve().parent.parent / "rafter_cli" / "resources" / "skills"
SKILLS = sorted(p.parent.name for p in SKILLS_DIR.glob("*/SKILL.md"))


def test_finds_the_skills_it_checks():
    assert len(SKILLS) >= 4


@pytest.mark.parametrize("name", SKILLS)
def test_skill_loads_without_an_approval(name):
    text = (SKILLS_DIR / name / "SKILL.md").read_text(encoding="utf-8")
    frontmatter = re.split(r"^---$", text, flags=re.M)[1]
    assert re.search(r"^name: ", frontmatter, re.M)
    assert re.search(r"^description: ", frontmatter, re.M)
    assert not re.search(r"^allowed-tools:", frontmatter, re.M)
