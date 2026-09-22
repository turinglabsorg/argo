import pytest

from argo.agent_models import apply_patches, edit
from argo.providers import CodingProfile


def test_apply_patches_replaces_a_unique_snippet_and_preserves_json_identifiers():
    original = "const app = express();\napp.use(express.json());\napp.listen(3000);\n"
    result = apply_patches(
        {"app.js": original},
        [{"path": "app.js", "old_text": "app.listen(3000);", "new_text": "app.listen(8080);"}],
    )
    assert result["app.js"] == "const app = express();\napp.use(express.json());\napp.listen(8080);\n"


def test_apply_patches_creates_a_new_file_with_empty_old_text():
    result = apply_patches({}, [{"path": "tests/argo-security/new.test.cjs", "old_text": "", "new_text": "test('ok', () => {});\n"}])
    assert result["tests/argo-security/new.test.cjs"] == "test('ok', () => {});\n"


def test_apply_patches_rejects_missing_duplicate_and_empty_overwrite():
    source = {"app.js": "token();\ntoken();\n"}
    with pytest.raises(ValueError, match="exactly once"):
        apply_patches(source, [{"path": "app.js", "old_text": "token();", "new_text": "keep();"}])
    with pytest.raises(ValueError, match="exactly once"):
        apply_patches(source, [{"path": "app.js", "old_text": "missing();", "new_text": "keep();"}])
    with pytest.raises(ValueError, match="new or empty file"):
        apply_patches(source, [{"path": "app.js", "old_text": "", "new_text": "replaced\n"}])
    with pytest.raises(ValueError, match="no edits"):
        apply_patches(source, [])


def test_coder_applies_unique_patches_without_rewriting_the_file(monkeypatch):
    original = "const app = express();\napp.use(express.json());\napp.listen(3000);\n"

    def respond(model, messages, *args, **kwargs):
        assert "old_text/new_text" in messages[0]["content"]
        return {"files": [{"path": "app.js", "edits": [{"old_text": "app.listen(3000);", "new_text": "app.listen(8080);"}]}]}

    monkeypatch.setattr("argo.agent_models.structured", respond)
    result = edit("Listen on 8080", ["app.js"], {"app.js": original})
    assert "express.json()" in result["app.js"]
    assert result["app.js"].endswith("app.listen(8080);\n")


def test_coder_forces_prompt_output_mode_for_source_edits(monkeypatch):
    captured = {}

    def respond(model, messages, *args, **kwargs):
        captured.update(kwargs)
        return {"files": [{"path": "app.py", "edits": [{"old_text": "value = 1", "new_text": "value = 2"}]}]}

    monkeypatch.setattr("argo.agent_models.structured", respond)
    profile = CodingProfile(name="Schema", protocol="openai", base_url="http://127.0.0.1:9", model="fixture", output_mode="json_schema")
    result = edit("Nudge the value", ["app.py"], {"app.py": "value = 1\n"}, profile=profile)
    assert result["app.py"] == "value = 2\n"
    assert captured["profile"].output_mode == "prompt"
    assert captured["profile"].model == "fixture"
    assert profile.output_mode == "json_schema"
