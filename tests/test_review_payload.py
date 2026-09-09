import copy
import hashlib
import json
import os
import time
from dataclasses import replace

import httpx
import pytest
from review_helpers import unpack_review as unpack
from test_finding_review import ASSESSMENT
from test_finding_review import review_case as review_case
from test_providers import endpoint

from argo.agent_models import (
    QWEN,
    REVIEWER,
    LocalModelError,
    local_structured,
    review_context_window,
    review_limits,
)
from argo.evidence import read_evidence, verify
from argo.finding_review import SCHEMA, SYSTEM
from argo.finding_validation import apply_result, hashes
from argo.review_payload import review_payload


def test_large_bound_finding_and_fix_send_every_value_once_when_repeated(review_case, monkeypatch):
    snapshot, store, records, _, run = review_case
    for index in range(6):
        snapshot.files[f'tests/support-{index}.txt'] = f'Original support file {index}: preserve every byte.\n' * 1450
    snapshot.files.update({f'lib/module-{index}.py': f'value = {index}\n' for index in range(100)})
    snapshot.manifests['yarn.lock'] = '# Original resolved dependency, complete metadata\n' * 3700
    original_files = copy.deepcopy(snapshot.files)
    snapshot.result['source_hashes'] = hashes({**snapshot.files, **snapshot.manifests})
    snapshot.result['support_hashes'] = hashes({path: content for path, content in snapshot.files.items() if path.startswith('tests/')})
    snapshot.result['cases'] = {role: {'source_hashes': snapshot.result['source_hashes'], 'stdout': 'Original runtime diagnostics\n', 'outcome': 'assertion_failed' if role == 'regression' else 'passed'} for role in snapshot.result['tests']}
    apply_result(snapshot.item, 'findings.test', snapshot.result, 'b' * 64)
    metadata = {'capabilities': ['completion', 'thinking'], 'model_info': {'general.architecture': 'qwen35', 'qwen35.context_length': 262144}}
    with endpoint('ollama', replies=lambda _: ASSESSMENT, metadata=metadata) as (local, requests):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        run()
        apply_result(snapshot.item, 'findings.verdict', {'state': 'reproduced', 'explanation': 'Protocol fixture reproduction'}, 'd' * 64)
        snapshot.files['access.py'] += '\nfixed = True\n'
        snapshot.result = copy.deepcopy(snapshot.result)
        snapshot.result['source_hashes'] = hashes({**snapshot.files, **snapshot.manifests})
        for case in snapshot.result['cases'].values():
            case.update(source_hashes=snapshot.result['source_hashes'], outcome='passed')
        snapshot.args.update(interpretation='fixed', test_evidence_id='c' * 64)
        apply_result(snapshot.item, 'findings.test', snapshot.result, 'c' * 64)
        run()
    chats = [request['body'] for request in requests if request['path'] == '/api/chat']
    assert len(chats) == 2
    for identity, chat in zip(records, chats, strict=True):
        saved = read_evidence(store.path, identity)['data']['result']
        payload = chat['messages'][-1]['content']
        assert saved['review_input']['encoding'] == 'shared-json-v1'
        assert saved['review_input']['sha256'] == hashlib.sha256(payload.encode()).hexdigest()
        assert unpack(payload) == saved['review_context']
        assert chat['options']['num_ctx'] <= 262144
        original = [{'role': 'system', 'content': SYSTEM}, {'role': 'user', 'content': json.dumps(saved['review_context'])}]
        with pytest.raises(LocalModelError, match='advertised context'):
            review_context_window(QWEN, original, SCHEMA, metadata)
    after = unpack(chats[-1]['messages'][-1]['content'])
    payloads = [chat['messages'][-1]['content'] for chat in chats]
    assert len(os.path.commonprefix(payloads)) > 0.8 * min(map(len, payloads))
    assert after['before']['files']['access.py'] == original_files['access.py']
    assert after['files']['access.py'] == snapshot.files['access.py']
    assert after['before']['runtime']['cases']['regression']['outcome'] == 'assertion_failed'
    assert after['runtime']['cases']['regression']['outcome'] == 'passed'
    assert after['runtime']['test_hashes'] == after['before']['runtime']['test_hashes']
    for path, content in original_files.items():
        if path.startswith('tests/'):
            assert after['files'][path] == after['before']['files'][path] == content
    store.manifest()
    assert verify(store.path)['status'] == 'verified'


@pytest.mark.parametrize('context', [
    {'first': 'Repeated original source\n' * 4000, 'second': 'Repeated original source\n' * 4000},
    {'runtime': {'$argo_ref': 'v1'}, 'first': 'Source\n' * 10000, 'second': 'Source\n' * 10000},
])
def test_shared_payload_roundtrip_and_reference_collision(context):
    original = copy.deepcopy(context)
    payload, encoding = review_payload(context)
    assert unpack(payload) == original == context
    assert encoding == ('json' if 'runtime' in context else 'shared-json-v1')


@pytest.mark.asyncio
@pytest.mark.parametrize('model,phase', [(QWEN, 'prefill'), (QWEN, 'large_prefill'), (QWEN, 'idle'), (QWEN, 'deadline'), (REVIEWER, 'prefill')])
async def test_qwen_prefill_wait_preserves_stream_idle_and_total_deadline(monkeypatch, model, phase):
    limits = replace(review_limits(model), read_timeout=0.1, deadline=0.25 if phase in {'deadline', 'large_prefill'} else 3)
    monkeypatch.setattr('argo.agent_models.review_limits', lambda _: limits)

    def chunks(_):
        if phase == 'idle':
            yield {'message': {'thinking': 'Fixture activity'}, 'done': False}
        time.sleep(0.5)
        yield {'message': {'content': json.dumps(ASSESSMENT)}, 'done': True}

    metadata = {'model_info': {'general.architecture': 'qwen35', 'qwen35.context_length': 262144}} if phase == 'large_prefill' else None
    messages = [{'role': 'user', 'content': 'Complete large context\n' * 17000}] if phase == 'large_prefill' else []
    with endpoint('ollama', chunks=chunks, metadata=metadata) as (local, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        if model == QWEN and phase in {'prefill', 'large_prefill'}:
            result = await local_structured(model, messages, SCHEMA, lambda: None, 4096, None, None)
            assert result == ASSESSMENT
        else:
            with pytest.raises(LocalModelError if phase == 'deadline' else httpx.ReadTimeout):
                await local_structured(model, messages, SCHEMA, lambda: None, 4096, None, None)
