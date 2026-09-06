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
- Legacy audit proposals remain `explain`/`review_evidence`. `agent.py` adds a separate executable loop: workspace read/list, coder edits, Python, pytest, Bandit, specialist review and policy-limited MCP. The model chooses `action` before `parameters`; validate both the envelope and the selected tool schema. Tool output never grants scope or configuration changes. Successful pytest against unchanged workspace contents is required before completing a changed-code task.
- Models: `argo-foundation-sec:8b` (analysis), `argo-vulnllm:7b` (source review), and `argo-coder:30b-a3b` (Qwen3-Coder, coordinator and separate coder call). `config/models.lock.json` pins all GGUF revisions and hashes. `agent_models.py` uses constrained `/api/chat`; advisory Foundation-Sec chat retains its native `/api/generate` template. All inference targets loopback Ollama; no cloud aliases or implicit fallback. Runtime-test template/schema changes with actual weights.
- `workspace.py` supervises disposable code containers without host mounts, socket or network. Non-root user, read-only root, tmpfs workspace, capabilities, process/memory/time/output limits are mandatory. `data/agent/worker.py` is immutable image code. Use descriptor-relative no-follow file operations and independently validate exported paths on the host. Never add model-selected Docker flags, executables or host paths.
- `worker/Dockerfile` pins the base digest and `worker/requirements.txt` hashes dependencies. Rebuild with `scripts/install_worker.py` after worker changes; runtime uses the recorded local image digest. `data/agent/remote.py` runs in a separate bridge-network container with no code workspace. It implements bounded HTTPS MCP with public DNS/IP pinning, JSON/SSE, sessions and no server callback execution.
- `mcp.py` intersects discovered schemas with operator endpoint/tool/argument policy. Default DeepWiki exposes only a fixed repository enum. Reject schema references and unknown tools; treat responses as untrusted. Public remote MCP works; authenticated/stdio MCP and cloud coder credentials remain unimplemented. Never place secrets in profiles.
- Agent output includes `code/`, `changes.diff`, hashed workspace evidence and `kind: isolated_agent` reports. `restore` verifies evidence before seeding a new container. TUI `/import`, `/reset`, `/diff`, `/mcp`, `/agent-demo` and agent-aware `/resume` share these functions. Models cannot apply changes to source projects.
- `sandbox.py` runs digest-pinned Semgrep/Gitleaks with fixed argument arrays, no network, reduced privileges, deadlines, and output limits. The CLI enables them with `--scanners`; TUI audits enable them by default. Gitleaks sees originals through stdin and retains only redacted results.
- `network.py` is the native scoped HTTP broker. `webchecks.py` provides bounded CORS and Git HEAD checks; the seeded SQLite validation protocol belongs to the local lab. There is no production HTTP API server, general network scanner, Nuclei/ZAP worker, or authenticated role-matrix workflow.
- `intelligence.py` uses typed OSV/NVD/EPSS/CISA KEV clients with explicit disclosure policy and offline cache behavior. The external CVE MCP sidecar remains disabled. Credential references exist in the design, but authenticated execution is not implemented.
- `evidence.py` stores private run directories under `~/.argo/runs`, SQLite state/events, redacted evidence JSON, integrity manifests, and Markdown/JSON reports. Evidence readers validate identifiers, regular-file bounds, and hashes. Local hashes are not signed attestations.
- `/resume` restores verified agent files for the next task or reopens a legacy report. It does not restart interrupted processes or replay side effects. Advisory conversation history is memory-only. Retest reports "not detected" separately from "fixed".

## Verification

Run `uv run ruff check src tests scripts`, `uv run python scripts/validate_design.py`, and `uv run pytest -q`. The full suite needs Docker, installed worker/scanner images and loopback fixture servers. It executes code, failing/passing regressions, isolation probes, symlink denials, descendant cancellation, MCP protocol contracts and TUI workspace continuation at both terminal widths. Model contract tests are fixtures; `argo agent-demo` separately exercises real local models and public MCP with independent implementation checks. `argo demo --scanners` remains the legacy audit smoke test. See `docs/validation.md` and `docs/isolated-agent.md` for boundaries and unmeasured evaluation gates.

`uv build` must include `data/tui.tcss`, scanner locks/rules, and `data/agent/*.py`. `scripts/capture_tui.py` exports Textual screenshots. CI builds the isolated worker before integration tests. Never equate model-generated tests or a scanner alert with independent security validation.
