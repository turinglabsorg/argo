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

- Python package: `src/argo`, managed with `uv.lock`. `argo` launches the Textual TUI. Plain text starts the isolated tool agent; `/chat` is advisory. CLI adds `agent`, `agent-demo`, `mcp-tools`, source `--import` and verified workspace `--continue` alongside the legacy engagement commands.
- `tui.py` and `data/tui.tcss` implement conversation, scope/authorization forms, findings, report/evidence viewers, and saved-run browsing. Follow `DESIGN.md`; test wide and 80-column terminals with Textual Pilot. Use worker threads and main-thread callbacks; never block the UI event loop with inference or scanners.
- `services.py` supplies shared readiness, run-path validation, and the owned synthetic demo. `controller.run` accepts progress and cancellation callbacks for the TUI. Escape requests cancellation; Ctrl+Q waits for active work to stop before closing.
- `contracts.py` defines strict Pydantic engagement, authorization, finding, package, and proposal models. `scope.py` canonicalizes targets and binds authorization to the full execution configuration with expiry. The structural JSON schema is separate from runtime checks.
- Legacy audit proposals remain `explain`/`review_evidence`. `agent.py` adds a separate executable loop: workspace read/list, coder edits, Python, pytest, Bandit, specialist review and policy-limited MCP. The model chooses `action` before `parameters`; validate both the envelope and the selected tool schema. Tool output never grants scope or configuration changes. Python edits require successful pytest against unchanged files. Other text edits explicitly record missing runtime verification.
- Preserve bounded assistant action/tool-result conversation turns and the original operator task. The separate coder must receive the task, current instruction, selected files and recent test feedback. Replacing this with a repeatedly serialized task lost context in live model tests. Python output is syntax-checked; new unavailable dependencies receive bounded repair attempts.
- Coding profiles in providers.py select Ollama, OpenAI Chat Completions-compatible or Anthropic Messages-compatible endpoints and arbitrary model IDs. The profile supplies coordination and coding. ModelSettings persists the selection atomically in ~/.argo/models.json. Legacy specialist audit/chat remains local. Never silently fall back to another provider.
- workspace.py uses the operator-selected read/write project mount from the CLI/TUI; only that directory is exposed. Disposable mode has no bind mounts. Use the operator UID/GID for mounted writes, no network, read-only root and resource limits. Inspect the exact mount and preserve descriptor-relative no-follow file access. Never accept model-selected Docker flags, paths or images.
- `worker/Dockerfile` pins the base digest and `worker/requirements.txt` hashes dependencies. Rebuild with `scripts/install_worker.py` after worker changes; runtime uses the recorded local image digest. `data/agent/remote.py` runs in a separate bridge-network container with no code workspace. It implements bounded HTTPS MCP with public DNS/IP pinning, JSON/SSE, sessions and no server callback execution.
- mcp.py intersects operator policy with discovered schemas. Public remote MCP works; authenticated/stdio MCP remains unimplemented. Reject references, regex constraints and unknown tools. Coding-provider credentials use Hush through a fixed provider_worker child; keys never enter settings, prompts or code workers.
- Reports retain kind: isolated_agent and include project and coding_profile. The launch directory is mounted read/write by default; /workspace selects it, /isolated and /import select disposable mode. Changes persist immediately. /resume never mounts a report-supplied path; --continue restores only to disposable mode. /reset retains the selected project.
- Agent tool records retain exit codes and test-file hashes. `agent_demo.py` checks the generated implementation in a fresh container and requires failing-then-passing unchanged regressions, production changes and independent controls. Validation runs before durable completion; failures must remain failed in the report, state and evidence. Redaction that changes exported code requires retesting.
- `sandbox.py` runs digest-pinned Semgrep/Gitleaks with fixed argument arrays, no network, reduced privileges, deadlines, and output limits. The CLI enables them with `--scanners`; TUI audits enable them by default. Gitleaks sees originals through stdin and retains only redacted results.
- `network.py` is the native scoped HTTP broker. `webchecks.py` provides bounded CORS and Git HEAD checks; the seeded SQLite validation protocol belongs to the local lab. There is no production HTTP API server, general network scanner, Nuclei/ZAP worker, or authenticated role-matrix workflow.
- `intelligence.py` uses typed OSV/NVD/EPSS/CISA KEV clients with explicit disclosure policy and offline cache behavior. The external CVE MCP sidecar remains disabled. Credential references exist in the design, but authenticated execution is not implemented.
- `evidence.py` stores private run directories under `~/.argo/runs`, SQLite state/events, redacted evidence JSON, integrity manifests, and Markdown/JSON reports. Evidence readers validate identifiers, regular-file bounds, and hashes. Local hashes are not signed attestations.
- `/resume` restores verified agent files for the next task or reopens a legacy report. It does not restart interrupted processes or replay side effects. Advisory conversation history is memory-only. Retest reports "not detected" separately from "fixed".

## Verification

Run `uv run ruff check src tests scripts`, `uv run python scripts/validate_design.py`, and `uv run pytest -q`. The full suite needs Docker, installed worker/scanner images and loopback fixture servers. It executes code, failing/passing regressions, isolation probes, symlink denials, descendant cancellation, MCP protocol contracts and TUI workspace continuation at both terminal widths. Model contract tests are fixtures; `argo agent-demo` separately exercises real local models and public MCP with independent implementation checks. `argo demo --scanners` remains the legacy audit smoke test. See `docs/validation.md` and `docs/isolated-agent.md` for boundaries and unmeasured evaluation gates.

`uv build` must include `data/tui.tcss`, scanner locks/rules, and `data/agent/*.py`. `scripts/capture_tui.py` exports Textual screenshots. CI builds the isolated worker before integration tests. Never equate model-generated tests or a scanner alert with independent security validation.

The 0.2 local validation recorded 85 passing tests, actual three-model SQL repair with public MCP, independent code-creation checks and real-model TUI continuation. See the run IDs and limits in `docs/validation.md`; these smoke checks do not establish broad model reliability. Scroll conversation updates after layout and verify restored agent guidance at both terminal widths.

## Version 0.3 interaction and validation

- F2 or /model opens ModelDialog with profiles, protocol, URL, model ID, discovery, a synthetic test, Hush name, JSON mode and token parameter. Persist only on Save; keep model selection independent of the project. Test both terminal widths and HTTP-to-Docker edits.
- Provider tests cover real HTTP request/stream contracts for both compatible protocols, auth delivery in the fixed child, errors, persistence and direct writes. Use temporary projects; legacy TUI tests explicitly pass project=None so they cannot modify the development checkout.
- Mounted projects expose all their files to generated Python. Do not claim they have no host-file access or no project secrets. Adapter snapshots omit hidden/dependency/build paths and remain bounded. In-flight conflict checks do not provide transactional isolation. Cancellation does not undo writes.
- Test actual models separately from protocol fixtures. API compatibility tests do not establish model quality or a connection to a paid vendor.
