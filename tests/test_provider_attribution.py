import json

import httpx
import pytest

from argo.providers import OPENROUTER_APP_URL, CodingProfile, exchange

SCHEMA = {'type': 'object', 'properties': {'ok': {'const': True}}, 'required': ['ok'], 'additionalProperties': False}


@pytest.mark.parametrize('protocol', ['openai', 'anthropic'])
@pytest.mark.parametrize('base_url', ['https://openrouter.ai/api/v1', 'https://OPENROUTER.AI:443/api/v1'])
def test_openrouter_attribution_reaches_discovery_and_generation(monkeypatch, protocol, base_url):
    calls = []

    def respond(request):
        calls.append(request)
        if request.method == 'GET':
            return httpx.Response(200, json={'data': [{'id': 'fixture-model'}]})
        if protocol == 'anthropic':
            return httpx.Response(200, json={'content': [{'type': 'text', 'text': '{"ok":true}'}], 'stop_reason': 'end_turn'})
        return httpx.Response(200, json={'choices': [{'message': {'content': '{"ok":true}'}, 'finish_reason': 'stop'}]})

    client = httpx.Client
    monkeypatch.setattr('argo.providers.httpx.Client', lambda **kwargs: client(transport=httpx.MockTransport(respond), **kwargs))
    profile = CodingProfile(protocol=protocol, base_url=base_url, model='fixture-model')
    assert exchange(profile, 'models', key='synthetic-fixture-key') == ['fixture-model']
    assert exchange(profile, 'generate', [{'role': 'user', 'content': 'Return JSON'}], SCHEMA, key='synthetic-fixture-key') == {'ok': True}
    assert len(calls) == 2
    for request in calls:
        assert request.headers['HTTP-Referer'] == OPENROUTER_APP_URL
        assert request.headers['X-OpenRouter-Title'] == 'Argo'
        assert request.headers['X-OpenRouter-Categories'] == 'cli-agent'
    auth = 'x-api-key' if protocol == 'anthropic' else 'Authorization'
    assert calls[-1].headers[auth] == ('synthetic-fixture-key' if protocol == 'anthropic' else 'Bearer synthetic-fixture-key')
    assert json.loads(calls[-1].content)['model'] == 'fixture-model'


@pytest.mark.parametrize('base_url', [
    'https://api.openai.com/v1',
    'https://api.anthropic.com/v1',
    'http://127.0.0.1:11434',
    'http://openrouter.ai/api/v1',
    'https://openrouter.ai.example.com/api/v1',
    'https://example.com/openrouter.ai/api/v1',
    'https://openrouter.ai:8443/api/v1',
])
def test_other_origins_do_not_receive_openrouter_attribution(monkeypatch, base_url):
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={'data': []})

    client = httpx.Client
    monkeypatch.setattr('argo.providers.httpx.Client', lambda **kwargs: client(transport=httpx.MockTransport(respond), **kwargs))
    assert exchange(CodingProfile(protocol='openai', base_url=base_url), 'models') == []
    assert len(calls) == 1
    assert not {'http-referer', 'x-openrouter-title', 'x-openrouter-categories'} & set(calls[0].headers)


@pytest.mark.parametrize('base_url,mode,expected', [
    ('https://openrouter.ai/api/v1', 'json_schema', True),
    ('https://openrouter.ai/api/v1', 'json_object', True),
    ('https://openrouter.ai/api/v1', 'prompt', False),
    ('https://compatible.example/v1', 'json_schema', False),
])
def test_json_routing_requires_parameter_support_only_on_openrouter(monkeypatch, base_url, mode, expected):
    calls = []
    def respond(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200, json={'choices': [{'message': {'content': '{"ok":true}'}, 'finish_reason': 'stop'}]})
    client = httpx.Client
    monkeypatch.setattr('argo.providers.httpx.Client', lambda **kwargs: client(transport=httpx.MockTransport(respond), **kwargs))
    profile = CodingProfile(protocol='openai', base_url=base_url, output_mode=mode)
    assert exchange(profile, 'generate', [], SCHEMA) == {'ok': True}
    assert calls[0].get('provider') == ({'require_parameters': True} if expected else None)
