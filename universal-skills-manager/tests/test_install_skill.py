import os
from pathlib import Path
import pytest
import sys

# Add scripts directory to path to import from install_skill
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from install_skill import _inject_frontmatter_extras, _get_frontmatter_extras_for_dest

def test_inject_frontmatter_extras(tmp_path):
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text("""---
name: test-skill
description: A test skill
version: 1.0.0
---
# Test Skill
Body content.
""")
    
    extras = {"type": "tool", "status": "approved"}
    _inject_frontmatter_extras(skill_md, extras)
    
    content = skill_md.read_text()
    assert "type: tool\n" in content
    assert "status: approved\n" in content
    assert "version: 1.0.0\n" in content
    assert "name: test-skill\n" in content
    assert "Body content." in content

def test_inject_frontmatter_extras_override_existing(tmp_path):
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text("""---
name: test-skill
description: A test skill
type: old_type
status: pending
---
# Test Skill
Body content.
""")
    
    extras = {"type": "tool", "status": "approved"}
    _inject_frontmatter_extras(skill_md, extras)
    
    content = skill_md.read_text()
    assert "type: tool\n" in content
    assert "status: approved\n" in content
    assert "type: old_type" not in content
    assert "status: pending" not in content

def test_get_frontmatter_extras_for_dest(monkeypatch):
    from sync_skills import TOOLS
    
    # Mock TOOLS
    test_tools = [
        {
            "id": "alef-agent",
            "name": "Alef Agent",
            "user_path": "~/.alef-agent/workspace/skills",
            "project_path": "",
            "frontmatter_extras": {"type": "tool", "status": "approved"},
        },
        {
            "id": "claude-code",
            "name": "Claude Code",
            "user_path": "~/.claude/skills",
            "project_path": ".claude/skills",
        }
    ]
    monkeypatch.setattr("install_skill.TOOLS", test_tools, raising=False)
    monkeypatch.setattr("sync_skills.TOOLS", test_tools, raising=False)
    
    alef_dest = Path("~/").expanduser() / ".alef-agent" / "workspace" / "skills" / "my-skill"
    claude_dest = Path("~/").expanduser() / ".claude" / "skills" / "my-skill"
    random_dest = Path("/tmp/random/path")
    
    # Assert
    assert _get_frontmatter_extras_for_dest(alef_dest) == {"type": "tool", "status": "approved"}
    assert _get_frontmatter_extras_for_dest(claude_dest) == {}
    assert _get_frontmatter_extras_for_dest(random_dest) == {}
