import json
import threading

import pytest
from test_providers import endpoint
from textual.widgets import Static, TabbedContent, TextArea

from argo.agent_models import ANALYST, QWEN, REVIEWER, SPECIALISTS, LocalModelError, review, review_team
from argo.context_budget import ModelLimits
from argo.controller import Cancelled
from argo.model_activity import analysis_text
from argo.providers import CodingProfile, save_profile
from argo.tui import COMMANDS, LOGO, ArgoApp


@pytest.mark.parametrize('model', [ANALYST, REVIEWER, QWEN])
def test_local_review_streams_user_facing_fields_and_batches_long_source(monkeypatch, model):
    result = {'summary': 'Review complete', 'suspected_findings': [{'path': 'app.py', 'issue': 'Unbound SQL value', 'remediation': 'Bind query parameters'}]}
    metadata = {'capabilities': ['completion', 'thinking'], 'model_info': {'general.architecture': 'qwen35', 'qwen35.context_length': 262144}} if model == QWEN else None
    with endpoint('ollama', replies=[result] * 10, metadata=metadata) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        updates = []
        source = 'value = 1\n' * 6000
        output = review(model, {'app.py': source}, on_text=updates.append)
    records = [record for record in records if record['path'] == '/api/chat']
    assert output['source_batches'] > 1
    assert len(records) == output['source_batches']
    reconstructed = ''.join(json.loads(record['body']['messages'][-1]['content'])['app.py'] for record in records)
    assert reconstructed == source
    assert any('Review complete' in text and 'Suspected issue: Unbound SQL value' in text for text in updates)
    assert 'Review complete' in updates[0]
    assert all('Private scratchpad' not in text for text in updates)
    assert all(record['body']['model'] == model for record in records)


def test_analysis_preview_ignores_thinking_and_renders_partial_json():
    assert analysis_text('{"summary":"Inspecting the query') == 'Inspecting the query'
    output = analysis_text(json.dumps({'thinking': 'Private scratchpad', 'summary': 'A "quoted" statement', 'suspected_findings': [{'path': 'app.py', 'issue': '[link=example]literal[/link]', 'remediation': 'Bind inputs'}]}))
    assert 'Private scratchpad' not in output
    assert 'A "quoted" statement' in output
    assert 'Suspected issue: [link=example]literal[/link]' in output


def test_native_reasoning_arrives_before_the_answer(monkeypatch):
    received = threading.Event()
    output = {'summary': 'Review complete', 'suspected_findings': []}
    thoughts, answers = [], []

    def chunks(body):
        assert body['think'] is True
        yield {'message': {'thinking': 'Inspecting ownership checks.\x1b[31m', 'content': ''}, 'done': False}
        assert received.wait(3), 'Reasoning must be delivered before answer generation completes'
        yield {'message': {'content': json.dumps(output)}, 'done': True, 'done_reason': 'stop'}

    def thinking(text):
        assert not answers
        thoughts.append(text)
        received.set()

    with endpoint('ollama', chunks=chunks) as (profile, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        result = review(ANALYST, {'app.py': 'value = 1'}, on_text=answers.append, on_reasoning=thinking)
    assert result['summary'] == 'Review complete'
    assert thoughts and '\x1b' not in thoughts[0]
    assert all('ownership checks' not in text for text in answers)


@pytest.mark.parametrize('model,temperature', [(ANALYST, 0.3), (REVIEWER, 0)])
def test_truncated_review_retries_only_inference_with_more_output(monkeypatch, model, temperature):
    final = {'summary': 'Reviewed', 'suspected_findings': []}
    def chunks(body):
        truncated = body['options']['num_predict'] == 4096
        return [{'message': {'content': '{"summary":' if truncated else json.dumps(final)}, 'done': True, 'done_reason': 'length' if truncated else 'stop'}]
    with endpoint('ollama', chunks=chunks, metadata={'capabilities': ['completion']}) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        statuses = []
        assert review(model, {'app.py': 'value = 1'}, on_status=statuses.append)['summary'] == 'Reviewed'
    requests = [record['body'] for record in records if record['path'] == '/api/chat']
    assert [body['options']['num_predict'] for body in requests] == [4096, 8192]
    assert all(body['think'] is False for body in requests)
    assert all(body['options']['temperature'] == temperature for body in requests)
    assert requests[0]['messages'][1:] == requests[1]['messages'][1:]
    assert 'previous generation exhausted' in requests[1]['messages'][0]['content']
    assert any('retrying' in text for text in statuses)


@pytest.mark.parametrize('chunks,category', [
    ([{'message': {'content': ''}, 'done': True, 'done_reason': 'length'}], 'length'),
    ([{'message': {'content': '{'}}], 'incomplete'),
    ([{'message': {'content': '{'}, 'done': True}], 'format'),
    ([{'message': []}], 'format'),
    ([{'error': 'Never display this raw server error'}], 'generation'),
])
def test_local_review_classifies_failure_without_raw_error_disclosure(monkeypatch, chunks, category):
    with endpoint('ollama', chunks=chunks) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        with pytest.raises(LocalModelError) as raised:
            review(ANALYST, {'app.py': 'value = 1'})
    assert raised.value.category == category
    assert 'Never display' not in str(raised.value)
    assert len([r for r in records if r['path'] == '/api/chat']) == (2 if category == 'length' else 1)


def test_cancellation_during_native_reasoning(monkeypatch):
    cancelled = False
    def thinking(_):
        nonlocal cancelled
        cancelled = True
    def check():
        if cancelled:
            raise Cancelled('Cancelled')
    chunks = [{'message': {'thinking': 'Checking access'}}, {'message': {'content': '{}'}, 'done': True}]
    with endpoint('ollama', chunks=chunks) as (profile, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        with pytest.raises(Cancelled):
            review(ANALYST, {'app.py': 'value = 1'}, check, on_reasoning=thinking)


@pytest.mark.parametrize('phase', ['loading', 'reasoning'])
def test_slow_qwen_can_be_cancelled_without_waiting_for_a_token(monkeypatch, phase):
    waiting, released = threading.Event(), threading.Event()

    def replies(_):
        if phase == 'loading':
            waiting.set()
            assert released.wait(3)
        return {'summary': 'Unused', 'suspected_findings': []}

    def chunks(_):
        if phase == 'reasoning':
            yield {'message': {'thinking': 'Review started'}, 'done': False}
            waiting.set()
            assert released.wait(3)

    def check():
        if waiting.is_set():
            raise Cancelled('Cancelled while waiting for Ollama')

    with endpoint('ollama', replies=replies, chunks=chunks) as (profile, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        try:
            with pytest.raises(Cancelled, match='waiting for Ollama'):
                review(QWEN, {'app.py': 'value = 1'}, check)
        finally:
            released.set()


def test_qwen_reserves_context_for_longer_reasoning_and_retries_only_truncation(monkeypatch):
    final = {'summary': 'Reviewed', 'suspected_findings': []}

    def chunks(body):
        assert body['model'] == QWEN and body['think'] is True
        assert body['options']['num_ctx'] == 32768
        assert body['options']['temperature'] == 0.6
        truncated = body['options']['num_predict'] == 8192
        yield {'message': {'content': json.dumps(final)}, 'done': True, 'done_reason': 'length' if truncated else 'stop'}

    with endpoint('ollama', chunks=chunks) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        statuses = []
        result = review(QWEN, {'app.py': 'value = 1'}, on_status=statuses.append)
    requests = [r['body'] for r in records if r['path'] == '/api/chat']
    assert result['summary'] == 'Reviewed'
    assert [r['options']['num_predict'] for r in requests] == [8192, 16384]
    assert requests[0]['messages'][1:] == requests[1]['messages'][1:]
    assert 'previous generation exhausted' in requests[1]['messages'][0]['content']
    assert any('16,384' in status for status in statuses)


@pytest.mark.parametrize('model,accepted', [(ANALYST, False), (QWEN, True)])
def test_qwen_transport_accepts_longer_reasoning_without_expanding_other_models(monkeypatch, model, accepted):
    final = {'summary': 'Reviewed', 'suspected_findings': []}
    chunks = [{'message': {'thinking': 'a' * (2 * 1024**2)}, 'done': False}, {'message': {'content': json.dumps(final)}, 'done': True}]
    thinking = []
    with endpoint('ollama', chunks=chunks) as (profile, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        if accepted:
            assert review(model, {'app.py': 'value = 1'}, on_reasoning=thinking.append)['summary'] == 'Reviewed'
            assert max(map(len, thinking)) <= 16000
        else:
            with pytest.raises(LocalModelError, match='2 MiB'):
                review(model, {'app.py': 'value = 1'})


def test_review_team_starts_three_requests_and_isolates_one_failure(monkeypatch):
    barrier = threading.Barrier(3, timeout=3)
    owner = threading.get_ident()
    completed, updates = [], []

    def chunks(body):
        barrier.wait()
        if body['model'] == REVIEWER:
            yield {'error': 'Internal details must stay private'}
        else:
            yield {'message': {'thinking': 'Reviewing the snapshot'}, 'done': False}
            yield {'message': {'content': json.dumps({'summary': body['model'], 'suspected_findings': []})}, 'done': True}

    def progress(model, **details):
        assert threading.get_ident() == owner
        updates.append((model, details))

    def result(model, value):
        assert threading.get_ident() == owner
        completed.append(value)

    with endpoint('ollama', chunks=chunks) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        results = review_team({'app.py': 'value = 1'}, on_progress=progress, on_result=result)
    assert [r['model'] for r in results] == list(SPECIALISTS.values())
    assert len(completed) == 3 and len([r for r in records if r['path'] == '/api/chat']) == 3
    assert sum(r['status'] == 'complete' for r in results) == 2
    assert results[1]['status'] == 'failed' and 'Internal details' not in str(results)
    assert {model for model, _ in updates} == set(SPECIALISTS.values())


def test_review_team_cancels_silent_workers_and_keeps_completed_results(monkeypatch):
    completed, released = threading.Event(), threading.Event()
    results = []

    def chunks(body):
        if body['model'] != ANALYST:
            assert released.wait(3)
            return
        yield {'message': {'content': json.dumps({'summary': 'Completed first', 'suspected_findings': []})}, 'done': True}

    def check():
        if completed.is_set():
            raise Cancelled('Stop remaining reviews')

    def result(model, value):
        results.append(value)
        completed.set()

    with endpoint('ollama', chunks=chunks) as (profile, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        try:
            with pytest.raises(Cancelled, match='remaining reviews'):
                review_team({'app.py': 'value = 1'}, check, on_result=result)
        finally:
            released.set()
    assert [r['model'] for r in results] == [ANALYST]


def test_local_review_cancellation_interrupts_before_next_batch(monkeypatch):
    requests = []
    def respond(*args, **kwargs):
        requests.append(args)
        return {'summary': 'Reviewed first batch', 'suspected_findings': []}
    def check():
        if requests:
            raise Cancelled('Cancelled')
    monkeypatch.setattr('argo.agent_models.review_batch', respond)
    with pytest.raises(Cancelled):
        review(ANALYST, {'app.py': 'value = 1\n' * 6000}, check)
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('size', [(80, 24), (140, 44)])
async def test_welcome_models_live_activity_and_cancellation(tmp_path, monkeypatch, size):
    monkeypatch.setattr('argo.tui.doctor', lambda: {'ollama': {'status': 'ready', 'local_models': [{'name': ANALYST}, {'name': REVIEWER}]}})
    monkeypatch.setattr('argo.tui.model_limits', lambda *_: ModelLimits(context_window=1048576, max_output_tokens=943718, source='Model API'))
    settings = tmp_path / 'models.json'
    save_profile(CodingProfile(protocol='openai', base_url='http://127.0.0.1:1/v1', model='meta/muse-spark-1.3-contributor'), settings)
    app = ArgoApp(tmp_path / 'runs', project=None, settings_path=settings)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        welcome = app.query_one('#welcome', Static)
        assert LOGO in str(welcome.render())
        assert welcome.region.bottom <= app.query_one('#status').region.y
        roster = str(app.query_one('#model-roster', Static).render())
        assert all(label in roster for label in ['Muse Spark', 'Foundation-Sec', 'VulnLLM-R', 'Qwen3.8 27B'])
        assert app.query_one('#model-roster', Static).region.height == (2 if size[0] == 80 else 1)
        assert '/agent-demo' not in COMMANDS
        await pilot.press('f3')
        assert app.query_one('#views', TabbedContent).active == 'models-tab'
        app.begin('Analysing source')
        app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': ANALYST})
        assert 'Loading model' in str(app.model_messages[ANALYST].render())
        app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': ANALYST, 'reasoning': 'Following the ownership check [bold]literally[/bold]'})
        assert 'reasoning' in str(app.model_messages[(ANALYST, 'reasoning')].render())
        app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': ANALYST, 'text': 'Checking query construction', 'provisional': True})
        await pilot.pause()
        assert 'Checking query construction' in app.query_one('#foundation-output', TextArea).text
        assert 'Following the ownership' in app.query_one('#foundation-output', TextArea).text
        assert 'provisional analysis' in str(app.model_messages[ANALYST].render())
        app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': ANALYST, 'text': 'Suspected issue: unbound SQL', 'provisional': False})
        assert app.transcript[-1][1] == 'Suspected issue: unbound SQL'
        assert any('Following the ownership' in text for _, text in app.transcript)
        app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': REVIEWER, 'text': 'Checking the proposed fix', 'provisional': True})
        app.cancel_event.set()
        app.finish()
        assert app.model_activity[REVIEWER]['state'] == 'Stopped'
        assert '1,048,576' in str(app.query_one('#coding-activity', Static).render())
        app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': QWEN, 'reasoning': 'Inspecting object ownership'})
        app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': QWEN, 'text': 'Suspected object access issue', 'provisional': False})
        assert 'Inspecting object ownership' in app.query_one('#qwen-output', TextArea).text
        assert 'Suspected object access issue' in app.query_one('#qwen-output', TextArea).text


@pytest.mark.asyncio
@pytest.mark.parametrize('size', [(80, 24), (140, 44)])
async def test_interleaved_reviewers_keep_independent_live_widgets(tmp_path, monkeypatch, size):
    monkeypatch.setattr('argo.tui.doctor', lambda: {'ollama': {'status': 'ready', 'local_models': []}})
    monkeypatch.setattr('argo.tui.model_limits', lambda *_: ModelLimits())
    app = ArgoApp(tmp_path / 'runs', project=None, settings_path=tmp_path / 'models.json')
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        app.begin('Parallel review')
        for model in SPECIALISTS.values():
            app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': model})
        for index in range(4):
            for model in SPECIALISTS.values():
                app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': model, 'text': f'Observation {index}', 'provisional': True})
        assert all(app.model_activity[model]['state'] == 'Working' for model in SPECIALISTS.values())
        assert len(app.model_messages) == 3
        assert len([entry for entry in app.transcript if 'provisional analysis' in entry[0]]) == 3
        app.progress({'run_id': 'a' * 32, 'stage': 'security.review', 'model': ANALYST, 'text': 'Completed', 'provisional': False})
        assert app.model_activity[REVIEWER]['state'] == app.model_activity[QWEN]['state'] == 'Working'
        app.cancel_event.set()
        app.finish()
        assert app.model_activity[ANALYST]['state'] == 'Response complete'
        assert app.model_activity[REVIEWER]['state'] == app.model_activity[QWEN]['state'] == 'Stopped'


@pytest.mark.asyncio
async def test_live_reasoning_follows_tail_but_preserves_manual_scrolling(tmp_path, monkeypatch):
    monkeypatch.setattr('argo.tui.doctor', lambda: {'ollama': {'status': 'ready', 'local_models': []}})
    monkeypatch.setattr('argo.tui.model_limits', lambda *_: ModelLimits())
    app = ArgoApp(tmp_path / 'runs', project=None, settings_path=tmp_path / 'models.json')
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press('f3')
        app.begin('Review')
        output = app.query_one('#qwen-output', TextArea)
        event = {'run_id': 'a' * 32, 'stage': 'security.review', 'model': QWEN}
        app.progress({**event, 'reasoning': '\n'.join(f'Check {index}' for index in range(40))})
        await pilot.pause()
        assert output.scroll_y > 0 and output.scroll_y == output.max_scroll_y
        output.scroll_home(animate=False)
        await pilot.pause()
        app.progress({**event, 'reasoning': '\n'.join(f'Check {index}' for index in range(50))})
        await pilot.pause()
        assert output.scroll_y == 0
