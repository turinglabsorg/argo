# Project editing and model endpoints — 2026-09-07

Version 0.3 changes the default to a writable project mount and adds coding-provider selection in the TUI. The previous validation record below describes the older disposable-only behavior.

## Runtime evidence

- Actual TUI run: 0fc9d660326c48a68e9645eb27b975f7.
- Coding and coordination used argo-coder:30b-a3b through Ollama's OpenAI-compatible endpoint at http://127.0.0.1:11434/v1, with JSON object mode.
- The project was a dedicated temporary directory mounted read/write. Its existing add(a, b) implementation incorrectly subtracted.
- The model read the source and test, ran the failing regression, changed calculator.py in the actual mounted directory, and reran the unchanged test successfully.
- The saved run completed with six tool calls and ten verified evidence files. A new container independently reran pytest successfully. The modified source remained on the host after container removal.
- OpenAI and Anthropic protocol integration fixtures independently exercised full coordination, code generation, mounted writes and pytest. They use real local HTTP servers with controlled model responses, not paid vendor inference.
- TUI tests selected both protocols through F2, saved endpoint/model settings, ran project edits and checked persistence after reopening at 140×44 and 80×24.
- Provider tests cover SSE, JSON responses, model discovery, proxy prefixes, response format/token options, 401 errors, Bearer and x-api-key delivery, and the fixed credential child. Synthetic credentials never appear in child output.
- Docker tests verify the single writable project mount, host-visible writes, inaccessible files outside the project, no Docker socket, and conflict rejection when an external editor changes a file during a model request.
- JavaScript text editing is tested separately and explicitly records missing runtime verification; no JavaScript execution support is claimed.

Hush was installed from its published release with a verified checksum. The actual provider credential bridge was tested with synthetic credentials. No paid OpenAI or Anthropic account was contacted, and no user API key was requested or inspected.

The worker was rebuilt from pinned inputs; the installed local image is sha256:a80d0719319c9e46fda5523b43ef11cbbb6f87cecf0a3e82c79174a8f8f47bac. Project access is intentionally broader than the earlier disposable mode: generated Python can read and write the selected directory. It has no other host mount or network access.

## Checks

### OpenRouter Muse Spark 1.3 Contributor

The authenticated OpenRouter profile uses https://openrouter.ai/api/v1 and meta/muse-spark-1.3-contributor with JSON schema mode. Its credential was imported directly from a user-provided Bitwarden Send into Hush and used only through the fixed provider child. No key value was inspected, persisted in profile settings or added to repository files.

Actual TUI run b9381aee41d24e9f82e9df85141a43a9 completed five tool calls: two source reads, a failing pytest run, a code edit and a passing pytest run. The model changed calculator.py in the mounted synthetic project while leaving the existing regression unchanged. A new container independently passed that regression, and all nine evidence files verified. The TUI loaded the persisted global profile and its connection Test succeeded against the real model.

The previous 256-token connection probe exhausted the model's output budget; the same structured request succeeded with 2,048 tokens. The probe now permits 2,048 tokens. A local HTTP/TUI regression fixture simulates a reasoning model that requires tokens before its JSON output and checks that truncated responses remain rejected.

### Local suite

After the OpenRouter probe fix, the local suite passed 101 tests in 49.66 seconds. Ruff and structural documentation validation passed; the 0.3 source distribution and wheel built successfully. The global editable argo command uses frozen dependency constraints and includes the probe fix. API compatibility and small smoke tasks do not establish arbitrary model reliability or broad pentest coverage.

---

# Local validation — 2026-09-06

This records smoke tests of Argo 0.2 and the earlier advisory MVP, not a model benchmark or a claim of complete pentest coverage. No third-party target was tested. The external MCP checks used public documentation tools.

## Environment

- Apple M1 Max, 64 GB unified memory, macOS 26.6.2.
- Python 3.12, Textual 8.2.8, Ollama 0.33.3, Docker 29.7.2.
- Ollama bound to loopback with cloud mode disabled, one loaded model, and sequential inference. The Foundation-Sec runtime reported its model allocation in GPU memory.
- Dependencies are resolved in `uv.lock`; scanner image digests are in `src/argo/data/scanners.lock.json`.

## Isolated coding agent — 0.2

Three actual local models were exercised together: Foundation-Sec and VulnLLM for security reviews, and `argo-coder:30b-a3b` for coordination and separate code-edit calls. The coder is Qwen3-Coder-30B-A3B-Instruct, using the pinned Unsloth Q4_K_M conversion. Its GGUF SHA-256 is `fadc3e5f8d42bf7e894a785b05082e47daee4df26680389817e2093056f088ad` and its Ollama manifest digest is `e632d51872729262097a1f69a000abe6ede221faaccc05f5d7b0dbcbed24edbd`. Ollama reported an 18.96 GiB GPU allocation. The conversion requires its own evaluation; upstream benchmark scores are not inherited.

The final worker image on this machine was `sha256:ff61ca09d173a113ccf968aaff1bae3b81c95ea62a8d4a045f244a8197c84e74`. Build inputs and dependencies are pinned in `worker/`; image identity is recorded by the installer. All generated code and independent implementation checks below ran in fresh offline containers.

### Autonomous vulnerability repair

Command: `argo agent-demo`. Run ID: `11eeadf664ab4d9b9f162461e081b828`.

The agent made 12 actual tool calls before finishing: source inspection, a live DeepWiki MCP call, both specialist model reviews, Bandit, generated pytest regressions, implementation repair and retesting.

- Bandit reported B608 before the fix and no findings after it.
- Before the fix, pytest reported **1 failed, 2 passed**: the injection input returned both users instead of an empty result.
- Qwen3-Coder changed the interpolated SQL to a parameterized SQLite query.
- After the fix, the same tests reported **3 passed**. Their SHA-256 remained `4a61264ae45f674a79a9fe55ed346f99425f82c3d30899cd1105db72434617f5`.
- A separate deterministic verifier checked the positive case, missing user, apostrophe handling, two injection inputs and unchanged database row count. It passed in a new container.
- The verifier confirmed that production code changed and the failing/passing test file was unchanged. Its result gates the saved completion status.
- All **18 evidence files** passed the manifest integrity check.

This demonstrates repair of the owned SQLite fixture, not arbitrary application security. Model review output remains suspected until independently validated.

### Code creation and TUI continuation

Run `2d09c28e0b6c4f91be826db40bf5122a` created `normalize.py` and separate pytest tests using actual Qwen3-Coder calls. All **7 tests passed**; a separate container checked whitespace, casing, empty strings and invalid types. All 7 evidence files verified.

The actual Textual event loop then restored that run and received an Italian request to rename the function parameter to `value`, support keyword invocation, add a regression and rerun tests. Run `04c5925c5553427cbcbbbab07e1a5336` completed with **8 tests passed**. A fresh container independently verified keyword and positional calls and invalid types. All 10 evidence files verified; the original run's source remained unchanged. Wide and narrow terminal captures are in `docs/assets/agent.svg` and `docs/assets/agent-small.svg`.

Initial experiments with a smaller Qwen2.5-Coder 7B were not selected. An earlier coordinator implementation lost task context and repeated reads; the current implementation retains bounded assistant/tool turns and forwards the original operator task and test feedback to the coder. A 30-second read timeout also failed during a cold Qwen3 load; the validated configuration uses 60 seconds with a separate 300-second generation budget. These successful smoke runs are not a reliability benchmark.

### Isolation, MCP and integration checks

- Real worker inspection confirmed no host mounts, no network, user 65532, read-only root, dropped capabilities and no privileged/host-PID mode.
- Host canary files, the Docker socket, root writes and connections to public, metadata and host gateway addresses were unavailable. Symlink read/write escapes were rejected.
- Cancellation removed the whole container, including detached descendants. An abruptly killed controller can leave a container; this development sandbox is not a malware-analysis VM.
- MCP protocol tests covered JSON/SSE responses, sessions, schema intersection, callback rejection and denied arguments/endpoints. Live discovery and `read_wiki_structure` succeeded against public DeepWiki from the separate broker container. The default profile only permits a fixed repository-name enum.
- TUI integration tests exercise code edits, tests, diffs, verified evidence, workspace continuation, reset and cancellation at 140×44 and 80×24 cells.
- The final suite contains **85 passing tests**, including real Docker workers/scanners and loopback fixtures. Model/provider contract tests use controlled responses; the live model and MCP runs above are separate.
- Ruff, structural design validation and source/wheel builds pass. The wheel includes the immutable worker/MCP adapters and TUI assets. The installed terminal command uses the frozen dependency versions.

Cloud models, authenticated or stdio MCP, general remote network scanning and automatic application of patches to original projects remain outside this runtime.

## Earlier advisory MVP validation

The following results describe the preceding read-only audit workflow and its original 59-test suite.

### Installed specialist models

Both GGUF files were downloaded from the revisions in `config/models.lock.json`, verified against the recorded SHA-256, and imported into local Ollama. No general model was used for the final audit or TUI chat checks.

| Model | Quantization | Ollama manifest digest |
| --- | --- | --- |
| Foundation-Sec-8B-Reasoning | Q4_K_M | `702c8b23150200baccedf1e9b8b1a764b91fb4ddf53850975fb2e4150e7714e4` |
| VulnLLM-R-7B | Q4_K_M | `fde20e7738c4a6038ab79646b1e04f0e056143222ec557cb7ae3656feb3a346f` |

Foundation-Sec uses the official Cisco quantization; VulnLLM uses a community conversion. Their licenses and upstream model cards remain authoritative: [Foundation-Sec](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning), [VulnLLM-R](https://huggingface.co/Virtue-AI-HUB/VulnLLM-R-7B).

### Full local audit

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

### TUI and chat

The Textual interface was exercised through its actual event loop and workers:

- Create a draft with the form; block execution before authorization; authorize and run the owned fixture.
- Reject authorization if the engagement changes while its review dialog is open.
- Browse findings, reopen saved runs, display reports and individual integrity-checked evidence records.
- Complete commands, recall prompt history, render untrusted markup literally, cancel work, and hide the sidebar at 80 columns.
- Render and inspect screenshots at 140×44 and 80×24 cells.
- Open the completed audit in the TUI and ask about its selected SQL finding using the real models. Foundation-Sec answered in Italian in 14.97 seconds; a VulnLLM follow-up answered in Italian in 16.14 seconds. Both responses referred to `app.py:2` and parameterized queries.

Foundation-Sec's imported chat behavior was inconsistent during initial free-text tests. The TUI now uses the native role format from its pinned tokenizer through Ollama's raw generation API; structured audit calls retain the independently tested JSON chat path. An observed exact repetition of the user's question is reported as a failed answer. Foundation-Sec officially supports English; successful Italian smoke answers do not establish general Italian accuracy. Model advice, including database-specific placeholder syntax, still requires verification against the actual application.

Conversation history remains in memory; saved audit reports persist under the private Argo state directory. Reopening a report does not resume an interrupted scanner or restore chat history.

### Automated and packaging checks

- `pytest -q`: **59 passed**. Includes real Docker scanners and loopback HTTP fixtures; provider/model contract tests use controlled responses.
- `ruff check src tests scripts`: passed.
- `scripts/validate_design.py`: structural schema and documentation checks, distinct from runtime tests.
- `uv build`: source distribution and wheel built successfully. The wheel contains the TUI, chat adapter, stylesheet, scanner lock, and rules.
- The terminal command was installed with dependency constraints exported from the lockfile.

The larger labeled/held-out evaluation corpus and its proposed precision/recall release gates remain unmeasured. A first real engagement still needs an operator-selected repository or staging origin.
