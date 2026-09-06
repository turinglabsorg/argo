# Local validation — 2026-09-06

This records smoke tests of the executable MVP, not a model benchmark or a claim of complete pentest coverage. No third-party target was tested.

## Environment

- Apple M1 Max, 64 GB unified memory, macOS 26.6.2.
- Python 3.12, Textual 8.2.8, Ollama 0.33.3, Docker 29.7.2.
- Ollama bound to loopback with cloud mode disabled, one loaded model, and sequential inference. The Foundation-Sec runtime reported its model allocation in GPU memory.
- Dependencies are resolved in `uv.lock`; scanner image digests are in `src/argo/data/scanners.lock.json`.

## Installed specialist models

Both GGUF files were downloaded from the revisions in `config/models.lock.json`, verified against the recorded SHA-256, and imported into local Ollama. No general model was used for the final audit or TUI chat checks.

| Model | Quantization | Ollama manifest digest |
| --- | --- | --- |
| Foundation-Sec-8B-Reasoning | Q4_K_M | `702c8b23150200baccedf1e9b8b1a764b91fb4ddf53850975fb2e4150e7714e4` |
| VulnLLM-R-7B | Q4_K_M | `fde20e7738c4a6038ab79646b1e04f0e056143222ec557cb7ae3656feb3a346f` |

Foundation-Sec uses the official Cisco quantization; VulnLLM uses a community conversion. Their licenses and upstream model cards remain authoritative: [Foundation-Sec](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning), [VulnLLM-R](https://huggingface.co/Virtue-AI-HUB/VulnLLM-R-7B).

## Full local audit

Command: `argo demo --scanners`.

Run ID: `7b35b88bfc964d6e8f16ac96e763af21`.

The fixture supplied a temporary source repository, synthetic package advisory, and paired vulnerable/fixed SQLite HTTP services. Semgrep and Gitleaks ran in the pinned isolated containers.

- Five normalized findings: four suspected observations and one confirmed SQL injection in the vulnerable fixture.
- The fixed HTTP control did not trigger the SQL injection finding.
- Foundation-Sec produced three valid, evidence-bound proposals in 75.28 seconds.
- VulnLLM produced one valid, evidence-bound proposal in 25.63 seconds.
- Four model requests, no invalid structured responses in this run.
- All 14 stored evidence files passed the local manifest integrity check.
- The report explicitly records unavailable general network scanning, authenticated workflows, Nuclei, and ZAP.

Audit inference used an 8,192-token context, temperature zero, a 1,600-token completion limit, schema-constrained output, and thinking disabled. Finding IDs and evidence references are constrained and validated in code. These timings describe a single fixture run and do not predict other engagements.

## TUI and chat

The Textual interface was exercised through its actual event loop and workers:

- Create a draft with the form; block execution before authorization; authorize and run the owned fixture.
- Reject authorization if the engagement changes while its review dialog is open.
- Browse findings, reopen saved runs, display reports and individual integrity-checked evidence records.
- Complete commands, recall prompt history, render untrusted markup literally, cancel work, and hide the sidebar at 80 columns.
- Render and inspect screenshots at 140×44 and 80×24 cells.
- Open the completed audit in the TUI and ask about its selected SQL finding using the real models. Foundation-Sec answered in Italian in 14.97 seconds; a VulnLLM follow-up answered in Italian in 16.14 seconds. Both responses referred to `app.py:2` and parameterized queries.

Foundation-Sec's imported chat behavior was inconsistent during initial free-text tests. The TUI now uses the native role format from its pinned tokenizer through Ollama's raw generation API; structured audit calls retain the independently tested JSON chat path. An observed exact repetition of the user's question is reported as a failed answer. Foundation-Sec officially supports English; successful Italian smoke answers do not establish general Italian accuracy. Model advice, including database-specific placeholder syntax, still requires verification against the actual application.

Conversation history remains in memory; saved audit reports persist under the private Argo state directory. Reopening a report does not resume an interrupted scanner or restore chat history.

## Automated and packaging checks

- `pytest -q`: **59 passed**. Includes real Docker scanners and loopback HTTP fixtures; provider/model contract tests use controlled responses.
- `ruff check src tests scripts`: passed.
- `scripts/validate_design.py`: structural schema and documentation checks, distinct from runtime tests.
- `uv build`: source distribution and wheel built successfully. The wheel contains the TUI, chat adapter, stylesheet, scanner lock, and rules.
- The terminal command was installed with dependency constraints exported from the lockfile.

The larger labeled/held-out evaluation corpus and its proposed precision/recall release gates remain unmeasured. A first real engagement still needs an operator-selected repository or staging origin.
