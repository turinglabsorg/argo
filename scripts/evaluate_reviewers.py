"""Run local reviewers on owned, executable positive and negative controls."""

import argparse
import hashlib
import json
import sqlite3
import time
from pathlib import Path

from argo.agent_models import SPECIALISTS, local_model_error, review, review_team
from argo.evidence import clean, private_dir, write_private

SOURCES = {
    'lookup_a.py': '''def find_user(connection, name):
    return connection.execute("SELECT id FROM users WHERE name = '" + name + "'").fetchall()
''',
    'lookup_b.py': '''def find_user(connection, name):
    return connection.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchall()
''',
    'download_a.py': '''def download_url(documents, current_user_id, document_id, signer):
    if current_user_id is None:
        return 401, None
    document = documents.get(document_id)
    if document is None:
        return 404, None
    return 200, signer(document["storage_path"])
''',
    'download_b.py': '''def download_url(documents, current_user_id, document_id, signer):
    if current_user_id is None:
        return 401, None
    document = documents.get(document_id)
    if document is None:
        return 404, None
    if document["owner_id"] != current_user_id:
        return 403, None
    return 200, signer(document["storage_path"])
''',
}


def verify_controls():
    namespaces = {}
    for name, source in SOURCES.items():
        namespace = {}
        exec(compile(source, name, 'exec'), namespace)
        namespaces[name] = namespace
    with sqlite3.connect(':memory:') as connection:
        connection.execute('CREATE TABLE users(id INTEGER, name TEXT)')
        connection.executemany('INSERT INTO users VALUES(?, ?)', [(1, 'alice'), (2, 'bob')])
        payload = "' OR 1=1 --"
        assert len(namespaces['lookup_a.py']['find_user'](connection, payload)) == 2
        assert namespaces['lookup_b.py']['find_user'](connection, payload) == []
        assert namespaces['lookup_b.py']['find_user'](connection, 'alice') == [(1,)]
    documents = {'d1': {'owner_id': 'alice', 'storage_path': 'private/alice.pdf'}}
    signed = []

    def signer(path):
        signed.append(path)
        return 'synthetic-signed-url'

    for name, expected in [('download_a.py', 200), ('download_b.py', 403)]:
        function = namespaces[name]['download_url']
        before = len(signed)
        assert function(documents, 'bob', 'd1', signer)[0] == expected
        assert len(signed) - before == (1 if expected == 200 else 0)
        assert function(documents, None, 'd1', signer)[0] == 401
        assert function(documents, 'alice', 'd1', signer)[0] == 200
    return {'positive': {'lookup_a.py': 'SQL injection', 'download_a.py': 'Missing object ownership check'}, 'negative': ['lookup_b.py', 'download_b.py']}


def evaluate(models, output, parallel=False):
    rubric = verify_controls()
    private_dir(output)
    started = time.monotonic()
    activity = {model: {'started': None, 'first_reasoning_seconds': None, 'first_answer_seconds': None, 'reasoning_updates': 0, 'answer_updates': 0} for model in models}
    results = []

    def progress(model, **details):
        item = activity[model]
        now = time.monotonic() - started
        if item['started'] is None:
            item['started'] = now
        for field, label in [('reasoning', 'reasoning'), ('text', 'answer')]:
            if details.get(field):
                item[label + '_updates'] += 1
                if item['first_' + label + '_seconds'] is None:
                    item['first_' + label + '_seconds'] = round(now, 2)
        if details.get('status'):
            print(json.dumps({'model': model, 'status': details['status']}), flush=True)

    def completed(model, result):
        entry = {'model': model, 'seconds': round(time.monotonic() - started - (activity[model]['started'] or 0), 2), 'activity': activity[model], 'result': result}
        results.append(entry)
        write_private(output / (model.replace(':', '-') + '.json'), json.dumps(clean(entry), indent=2) + '\n')
        print(json.dumps({'model': model, 'status': result.get('status'), 'seconds': entry['seconds'], 'findings': len(result.get('suspected_findings', []))}), flush=True)

    if parallel:
        if set(models) != set(SPECIALISTS.values()):
            raise ValueError('Parallel evaluation requires the three configured reviewers')
        review_team(SOURCES, on_progress=progress, on_result=completed)
    else:
        for model in models:
            progress(model, status='Loading model')
            try:
                result = {'model': model, 'status': 'complete', **review(model, SOURCES, on_text=lambda text: progress(model, text=text), on_reasoning=lambda text: progress(model, reasoning=text), on_status=lambda text: progress(model, status=text))}
            except Exception as exc:
                result = {'model': model, 'status': 'failed', 'error': local_model_error(exc)}
            completed(model, result)
    report = {'seconds': round(time.monotonic() - started, 2), 'execution': 'concurrent' if parallel else 'sequential', 'source_sha256': {name: hashlib.sha256(source.encode()).hexdigest() for name, source in SOURCES.items()}, 'verified_controls': rubric, 'reviews': results, 'note': 'Four small controls in one source review. Judge issue descriptions, not just paths. This does not establish broad security accuracy.'}
    write_private(output / 'report.json', json.dumps(clean(report), indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', choices=[*SPECIALISTS, 'all'], required=True)
    parser.add_argument('--output', type=Path, required=True, help='New private result directory')
    parser.add_argument('--sequential', action='store_true')
    args = parser.parse_args()
    models = list(SPECIALISTS.values()) if args.model == 'all' else [SPECIALISTS[args.model]]
    evaluate(models, args.output, parallel=args.model == 'all' and not args.sequential)


if __name__ == '__main__':
    main()
