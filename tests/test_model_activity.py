import json
import threading

import pytest
from test_providers import endpoint
from textual.widgets import Static, TabbedContent, TextArea

from argo.agent_models import ANALYST, REVIEWER, LocalModelError, review
from argo.context_budget import ModelLimits
from argo.controller import Cancelled
from argo.model_activity import analysis_text
from argo.providers import CodingProfile, save_profile
from argo.tui import COMMANDS, LOGO, ArgoApp


@pytest.mark.parametrize('model', [ANALYST, REVIEWER])
def test_local_review_streams_user_facing_fields_and_batches_long_source(monkeypatch, model):
    result = {'summary': 'Review complete', 'suspected_findings': [{'path': 'app.py', 'issue': 'Unbound SQL value', 'remediation': 'Bind query parameters'}]}
    with endpoint('ollama', replies=[result] * 10) as (profile, records):
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


def test_truncated_review_retries_only_inference_with_more_output(monkeypatch):
    final = {'summary': 'Reviewed', 'suspected_findings': []}
    def chunks(body):
        truncated = body['options']['num_predict'] == 4096
        return [{'message': {'content': '{"summary":' if truncated else json.dumps(final)}, 'done': True, 'done_reason': 'length' if truncated else 'stop'}]
    with endpoint('ollama', chunks=chunks, metadata={'capabilities': ['completion']}) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        statuses = []
        assert review(REVIEWER, {'app.py': 'value = 1'}, on_status=statuses.append)['summary'] == 'Reviewed'
    requests = [record['body'] for record in records if record['path'] == '/api/chat']
    assert [body['options']['num_predict'] for body in requests] == [4096, 8192]
    assert all(body['think'] is False for body in requests)
    assert requests[0]['messages'] == requests[1]['messages']
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
        assert all(label in roster for label in ['Muse Spark', 'Foundation-Sec', 'VulnLLM-R'])
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
