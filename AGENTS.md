# Argo development instructions

- This repository contains an executable MVP and its longer-term architecture. Keep README capabilities and roadmap status aligned with runtime-tested behavior.
- Keep code, documentation, comments, and commits in English.
- Follow `docs/architecture.md` for execution boundaries and `docs/roadmap.md` for implementation order.
- Do not interpret sample targets or a populated JSON file as authorization to run a test.
- Keep scope enforcement in deterministic code outside model prompts. Every action requires a typed, validated contract.
- Do not add a general shell tool to the model-facing interface. Use fixed executables and argument arrays in reviewed adapters.
- Do not expose the Docker socket, host home directory, cloud CLI credentials, SSH agent, or secret vault to workers.
- Use Hush for credentials, with output redaction; never store credential values in configuration, prompts, fixtures, logs, or reports.
- Use static imports. Add integration tests for backend functions and adapter behavior, including denial cases and failure paths.
- Runtime-test behavior changes before committing or pushing. Do not count type checking alone as runtime validation.
- Keep fixture tests offline and isolated. A live test requires an explicitly selected engagement.
- Keep dependency versions, scanner images, rule packs, and model artifacts pinned and attributable.
- Do not add tool or assistant co-authorship to commits or pull requests.

## Implemented runtime

- Python package: `src/argo`, managed with `uv.lock`. `argo` launches the Textual TUI on a terminal; `argo tui [engagement.json]` opens a case explicitly. CLI commands cover doctor, init, plan, authorize, run, demo, runs, status, stop, report, verify, and retest.
- `tui.py` and `data/tui.tcss` implement conversation, scope/authorization forms, findings, report/evidence viewers, and saved-run browsing. Follow `DESIGN.md`; test wide and 80-column terminals with Textual Pilot. Use worker threads and main-thread callbacks; never block the UI event loop with inference or scanners.
- `services.py` supplies shared readiness, run-path validation, and the owned synthetic demo. `controller.run` accepts progress and cancellation callbacks for the TUI. Escape requests cancellation; Ctrl+Q waits for active work to stop before closing.
- `contracts.py` defines strict Pydantic engagement, authorization, finding, package, and proposal models. `scope.py` canonicalizes targets and binds authorization to the full execution configuration with expiry. The structural JSON schema is separate from runtime checks.
- Model actions are only `explain` and `review_evidence`. Audit proposals are schema-constrained, reference existing findings/evidence, and cannot execute tools. Free-text chat is advisory. Audit execution starts through explicit operator commands.
- Only `argo-foundation-sec:8b` and `argo-vulnllm:7b` are offered. `config/models.lock.json` pins GGUF revisions and hashes. Audit inference uses Ollama `/api/chat`; Foundation-Sec TUI chat uses its native role template via `/api/generate`, while VulnLLM chat uses `/api/chat`. Readiness uses `/api/tags`. All model calls target `127.0.0.1:11434`; reject cloud aliases. Test actual local models after changing templates or reasoning handling, not just mocked responses.
- `sandbox.py` runs digest-pinned Semgrep/Gitleaks with fixed argument arrays, no network, reduced privileges, deadlines, and output limits. The CLI enables them with `--scanners`; TUI audits enable them by default. Gitleaks sees originals through stdin and retains only redacted results.
- `network.py` is the native scoped HTTP broker. `webchecks.py` provides bounded CORS and Git HEAD checks; the seeded SQLite validation protocol belongs to the local lab. There is no production HTTP API server, general network scanner, Nuclei/ZAP worker, or authenticated role-matrix workflow.
- `intelligence.py` uses typed OSV/NVD/EPSS/CISA KEV clients with explicit disclosure policy and offline cache behavior. The external CVE MCP sidecar remains disabled. Credential references exist in the design, but authenticated execution is not implemented.
- `evidence.py` stores private run directories under `~/.argo/runs`, SQLite state/events, redacted evidence JSON, integrity manifests, and Markdown/JSON reports. Evidence readers validate identifiers, regular-file bounds, and hashes. Local hashes are not signed attestations.
- `/resume` reopens a saved report; it does not restart an interrupted scanner or recover chat history. Conversation history is memory-only. Retest reports "not detected" separately from "fixed".

## Verification

Run `uv run ruff check src tests scripts`, `uv run python scripts/validate_design.py`, and `uv run pytest -q`. The full integration suite needs Docker and loopback fixture servers; `-m 'not live'` skips Docker-dependent tests. Provider and model contract tests are controlled fixtures. `argo demo --scanners` separately exercises the installed cyber models and real scanners against owned vulnerable/fixed fixtures. See `docs/validation.md` for observed results and unmeasured evaluation gates.

`uv build` must include `data/tui.tcss`, the scanner lock, and rule files. `scripts/capture_tui.py` exports Textual screenshots. The GitHub workflow runs pinned dependency installation, lint, structural checks, scanner installation, and integration tests on Ubuntu.
