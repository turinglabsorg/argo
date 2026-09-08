import json

import pytest
from test_providers import endpoint

from argo.agent_models import QWEN, LocalModelError, review_response
from argo.context_budget import estimate_tokens


@pytest.mark.parametrize("advertised", [262144, None, True, "262144", 0])
def test_complete_before_and_after_context_fits_or_fails_without_truncation(monkeypatch, advertised):
    lockfile = "dependency@1.2.3:\n  version 1.2.3\n" * 5500
    context = {"before": {"lockfile": lockfile, "source": "return True"},
               "after": {"lockfile": lockfile, "source": "return owner == actor"}}
    messages = [{"role": "system", "content": "Assess the complete source and dependency snapshots."},
                {"role": "user", "content": json.dumps(context)}]
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}
    metadata = {"capabilities": ["completion"], "model_info": {
        "general.architecture": "qwen35", "qwen35.context_length": advertised,
        "unrelated.context_length": 100_000_000,
    }}
    with endpoint("ollama", metadata=metadata) as (local, requests):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", local.base_url)
        if type(advertised) is int and advertised == 262144:
            assert review_response(QWEN, messages, schema, lambda: None) == {"ok": True}
        else:
            with pytest.raises(LocalModelError, match="advertised context"):
                review_response(QWEN, messages, schema, lambda: None)
    chats = [r["body"] for r in requests if r["path"] == "/api/chat"]
    if type(advertised) is int and advertised == 262144:
        assert len(chats) == 1
        assert chats[0]["messages"] == messages
        assert 131072 < chats[0]["options"]["num_ctx"] <= advertised
        assert chats[0]["options"]["num_ctx"] > estimate_tokens(messages) + estimate_tokens(schema) + 16384
    else:
        assert not chats
