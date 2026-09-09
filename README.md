# Argo

Review code. Investigate security issues. Apply fixes and verify them.

Argo is a terminal agent with specialist local security models and your choice of local or remote coding endpoint. It edits the project you open and executes Python and targeted Node.js security tests in Docker.

Launch Argo from a project directory: that directory is mounted read/write, and edits immediately change its files. F2 or /model selects any model ID through an Ollama, OpenAI-compatible or Anthropic-compatible endpoint. The selected model coordinates tools and writes code. By default, Qwen3.8 27B reviews each conclusive finding and its fix automatically. Foundation-Sec and VulnLLM provide additional security opinions; all three can also review source individually or in parallel.

Code executes in a non-root, offline container with only the selected project mounted. Provider credentials, the Docker socket and other host directories are not mounted. Files inside the selected project are accessible to its code. A separate immutable broker connects to configured remote MCP tools.

![Argo terminal welcome](docs/assets/welcome.svg)

## Install

Requirements: Python 3.12+, uv and Docker. Native Ollama with `argo-qwen:27b` is required for conclusive finding verification and verified fixes, including with a remote coding endpoint. General coding tasks without findings can use a remote endpoint alone.

    uv sync --frozen --dev
    uv run python scripts/install_worker.py
    uv run argo doctor

Install the terminal command with frozen dependency versions:

    uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file /tmp/argo-constraints.txt >/dev/null
    uv tool install --editable . --python 3.12 --constraints /tmp/argo-constraints.txt

To install the local models, start Ollama and run:

    uv run python scripts/install_models.py

To install or resume only the coder:

    uv run python scripts/install_models.py --model argo-coder:30b-a3b

The installer verifies the pinned GGUF hashes and can reuse a verified source blob already in native Ollama storage (`OLLAMA_MODELS` or `~/.ollama/models`). New downloads reserve room for four model-sized copies plus 5 GiB because Ollama conversion and validation can create temporary duplicates. The --parallel option accepts 1–32 download connections. Local aliases are defaults, not an allowlist for coding:

| Alias | Model | Role |
| --- | --- | --- |
| argo-coder:30b-a3b | Qwen3-Coder-30B-A3B-Instruct, Unsloth Q4_K_M | Default coding and coordination |
| argo-foundation-sec:8b | Foundation-Sec-8B-Reasoning, official Q4_K_M | Optional security analysis |
| argo-vulnllm:7b | VulnLLM-R-7B, community Q4_K_M | Optional source review |
| argo-qwen:27b | Qwen3.8-27B Heretic ARA, community Q4_K_M | Required finding/fix review; experimental model |

Install only the third reviewer with `uv run python scripts/install_models.py --model argo-qwen:27b`. It downloads a checksum-pinned 16.8 GB GGUF.

Ask Argo to “review these files with all three local models in parallel” to use `security.review_all`, or name Qwen for an individual `security.review`. The reviewers receive the same read-only source snapshot; the selected coding model compares their responses and performs any authorized edits. Ollama may queue requests when memory is insufficient. Completed reviews are saved independently, including when another reviewer fails or is cancelled.

See [model provenance](config/models.lock.json). The legacy audit/chat commands retain local specialist adapters. Mandatory finding reviews stay local regardless of the selected coding provider.

## Choose your coding model

Run argo, press **F2** or enter **/model**, then select or create a profile. The main form contains only the connection essentials; **Advanced** contains profile naming, response format and token overrides:

1. Choose Ollama, OpenAI-compatible or Anthropic-compatible.
2. Enter your base URL and model ID.
3. Optionally select a Hush credential by name.
4. Use Find models to discover IDs, or enter one manually.
5. Test checks structured output without sending project source. Save applies the profile to subsequent coding and coordination calls.

Profiles persist in ~/.argo/models.json and are also used by the CLI. Saving does not change the selected project.

OpenAI-compatible profiles use Chat Completions; Anthropic-compatible profiles use Messages. HTTP(S) hosts, custom ports, proxy prefixes and arbitrary model IDs are supported. URLs can end at the API root or the full generation path. OpenAI profiles offer prompt-only JSON, JSON object and JSON schema modes, plus max_tokens or max_completion_tokens. Unsupported capabilities produce visible errors; Argo does not silently switch providers.

OpenRouter was validated with base URL https://openrouter.ai/api/v1, model meta/muse-spark-1.3-contributor, JSON schema mode and max_tokens. The connection probe starts with 2,048 output tokens and can increase the allowance on truncation within the selected model budget. The [Contributor tier](https://openrouter.ai/meta/muse-spark-1.3-contributor) permits prompts and outputs to be used to improve Meta's products.

Requests to the official HTTPS OpenRouter endpoint identify the app as **Argo**, using the project repository URL and the `cli-agent` category. This enables [OpenRouter app attribution](https://openrouter.ai/docs/app-attribution) in usage analytics. API-key names and app attribution are separate; changing the key's label alone does not identify the app. Attribution headers use fixed public project metadata and are not added to other providers.

OpenRouter requests use a stable session identifier per run and role (coordination, coding and compaction) for [cache-aware routing](https://openrouter.ai/docs/guides/best-practices/prompt-caching). Provider usage evidence retains reported input/cache tokens, costs and generation IDs, including available counters from unsuccessful attempts. Reports show the share of measured input tokens read from cache; missing counters remain unknown. Cache reuse depends on the upstream provider and the unchanged prompt prefix. Session identifiers and OpenRouter streaming options are not sent to other endpoints.

For authentication, install [Hush](https://github.com/turinglabsorg/hush), import the credential from Bitwarden with hush pull --name NAME, then enter only NAME in the form. Argo invokes hush run --redact and injects the key into a fixed provider process. API keys are never saved in model settings or sent to code workers. Leave the credential field empty for endpoints without authentication. Selecting a remote endpoint sends task context and selected source to it.

![Coding endpoint and model selection](docs/assets/model-settings.svg)

## Context and auto-compact

Argo reads the selected model's limits from its API, caches them for five minutes and refreshes them at the start of each task. OpenRouter reports **1,048,576 context tokens** and **943,718 maximum completion tokens** for Muse Spark 1.3 Contributor (verified September 7, 2026). The output ceiling uses the advertised maximum and remaining context. The initial allowance scales with prompt size and the model window, growing on truncation without replaying tools; there is no fixed 2,000-token coordinator ceiling. F2 allows optional context/output overrides; leave both blank for automatic limits.

Before each coordination request, Argo estimates token use from UTF-8 text and retains a 10% safety margin plus a response reserve. This is an estimate, not the provider's exact tokenizer count. At 90% of the input budget, auto-compact summarizes older history, retaining the original task, the deterministic completed-tool ledger and recent results. It saves a verified compaction record and context.json before the next action. Failed compaction does not discard history or replay tools. F3 shows the context limit, estimated use and compaction count.

Endpoints that do not publish context limits use an explicitly labelled 16,384-token fallback; set an override in F2 when the endpoint requires it. Foundation-Sec and VulnLLM reviews use 16,384-token contexts; Qwen reviews start at 32,768 and grow to fit complete evidence, within the installed model capacity advertised by Ollama. These local allocations are independent of the coding provider context. Large specialist reviews are split into source batches; cross-batch findings still require verification. Foundation-Sec uses temperature 0.3 and allows up to 20 minutes per inference, with a separate two-minute idle timeout and immediate cancellation, so active reasoning can continue past the old five-minute cutoff.

If a local review still exhausts its expanded output allowance, Argo retries smaller source batches, with at most two subdivision levels. Successful batches are retained; a terminal failure preserves partial evidence and lists the paths still unreviewed. Transient local connection failures receive one retry. These retries repeat inference only and do not reapply edits or rerun tests.

Reports, summaries and evidence persist. A new task currently starts a new conversation over the selected project or restored files; /resume reopens results, including local model responses, and does not replay actions or automatically load old conversation memory.

## Edit the project you open

    cd /path/to/project
    argo

Write a task directly in the TUI. The directory is mounted at /workspace, and code changes persist there, including when a later test fails or the task is cancelled. Argo checks whether selected files changed while the coding request was in flight before writing the response. Reports, code snapshots and changes.diff are also saved under ~/.argo/runs/RUN_ID/.

CLI equivalents:

    argo agent 'Fix this code and run the regression tests'
    argo agent 'Audit the code and apply fixes' --project /absolute/path/to/project
    argo agent 'Create a URL parser with pytest tests' --isolated
    argo agent 'Add regression tests' --continue RUN_ID

The default is the current directory. --isolated, --import and --continue use disposable workspaces instead. A saved snapshot cannot overwrite a mounted project. Home and filesystem root are rejected as project mounts.

Python implementation changes require passing pytest before completion. Dedicated finding regressions can intentionally fail while demonstrating a defect; they are tracked separately from implementation fixes. Other text files can be edited, with missing runtime verification explicitly recorded. Python 3.12, pytest, Bandit and Node.js 22 are installed. The `node.tests` tool runs tests/argo-security/*.test.cjs against already available project dependencies. Network package installation is unavailable; targeted controls do not establish full project test coverage. See [runtime contracts and limits](docs/isolated-agent.md).

Every finding enters a mandatory verification queue. The coordinator creates a secure-behavior regression and separate positive/negative controls against actual project code, runs them through `findings.test`, inspects the output and records `reproduced`, `refuted` or `inconclusive` with `findings.verdict`. The Findings tab shows the result, test paths and evidence. Refuted means the specific claim was contradicted in that tested scenario; generated tests are not independent security certification. Skips, setup errors and unavailable dependencies do not count as refutations. Explicit blockers remain incomplete coverage, and pending/stale findings block completion. Source or associated test edits require a fresh test run.

After reproduction, Argo locks the original tests and helpers. It can repair the implementation, rerun the same regression and controls, and record `fixed` only when they all pass after a real source change. The Findings tab retains the original failing evidence alongside the passing retest. `project.tests` also runs an already installed Vitest suite; a failed, empty, skipped or outdated attempted suite blocks completion of an edit. Dependencies must be available for the Linux worker.

`findings.verdict` automatically asks Qwen to assess the finding before accepting `reproduced` or `refuted`, then to compare original and repaired code before accepting `fixed`. Qwen receives the actual tests and runtime evidence. A missing, incomplete or dissenting review leaves verification open; an explicit blocker keeps the run incomplete. Generic source reviews cannot satisfy these checks. The Findings tab shows both assessments and evidence IDs, and Models shows live activity. Accepted reviews can be reused only for identical finding, verdict, test evidence and context; source changes require retesting and review. Model agreement adds scrutiny, not independent security certification.

The default mounted-project budget starts at 24 plus the visible file count (up to 256), then adds eight actions per finding, capped at 1,024; disposable fixtures retain the 24-action base; existing time, context and workspace limits still apply. `--max-steps` selects a strict 1–40 action cap instead. Exhausted limits preserve pending work in the report and never turn untested findings into a clean result.

To work without local specialist inference, use `argo agent 'TASK' --skip-local-reviews`, or `/reviews off` before starting a TUI task. This explicitly skips Qwen finding/fix approval and removes all local specialist tools for that run. The selected coding profile still coordinates, authors tests and edits code; select a remote profile to keep inference off the computer. Runtime tests, unchanged regression/control requirements, source bindings and incomplete-finding checks remain enforced. Reports visibly record the skipped reviews and never imply Qwen approval. The CLI flag applies to one run; the TUI choice lasts for the current app session. `/reviews on` restores the default. Saved reports and model responses cannot change this setting.

### Local test database

Use `/test-db mongodb` in the TUI, or `argo agent 'TASK' --test-database mongodb`, to start a fresh MongoDB for the task. The selection in the TUI lasts for the current app session; `/test-db off` disables it. Tests receive `ARGO_TEST_MONGODB_URI`. Connect with the project's existing MongoDB driver instead of starting or downloading a database binary.

The database shares only the worker's loopback network, has no project mount or published ports, and stores synthetic data in temporary memory. Both containers are removed on completion, failure or cancellation. The worker keeps external networking disabled. Native test-runner dependencies must still be available for Linux; selecting a database does not install them.

Within an enabled task, Argo can call `test.database.reset` to start its temporary database empty before a retest. Project files and the original regression tests stay unchanged. Tests must seed their own data after each reset.

Install the pinned database image once with `uv run python scripts/install_test_database.py`.

## Terminal controls

The TUI uses [Textual](https://github.com/Textualize/textual) under MIT.

| Interaction | Command |
| --- | --- |
| Create or change code | Type a task or /agent TASK |
| Select coding endpoint and model | F2 or /model |
| Show or change the mounted project | /workspace or /workspace PATH |
| Select an isolated test database | /test-db mongodb, /test-db off |
| Switch to a disposable workspace | /isolated |
| Copy sanitized sources into disposable mode | /import PATH |
| Reset context while retaining the selected project | /reset |
| Review changes already made | /diff |
| See all model roles and live analysis | F3 or /models |
| Configure CVE intelligence | /cve, /cve connected, /cve offline |
| Configure remote MCP | /mcp, /mcp off, /mcp PROFILE.json |
| Discuss findings without execution | /chat QUESTION |
| Choose the separate advisory chat model | /model foundation or /model vulnllm |
| Saved runs and reports | /runs, /resume RUN_ID, /report |
| Inspect verified tool/finding evidence | /evidence or /evidence ID |
| Service readiness | /doctor |
| Stop active work | Escape or /stop |

Tab completes commands; up/down recall prompts. Ctrl+L focuses input, Ctrl+R opens runs, F1 shows help, and Ctrl+Q stops work before closing. The sidebar hides below 100 columns. The selected coder and all three local reviewers remain visible in the header; F3 opens their roles, activity and live responses. Local source reviews stream exposed reasoning separately from provisional analysis. Reasoning remains visible during the current session when the endpoint emits it; only validated final responses are saved as tool evidence. Foundation-Sec advertises native thinking; the installed VulnLLM endpoint currently does not. Findings appear during the run and remain available after reopening it. Older structured script/model observations are recovered from verified evidence and stay suspected.

Resuming a mounted-project report does not change the selected directory. Disposable runs restore verified files into a new disposable workspace. Report contents never grant permission to mount another path, and interrupted side effects are never replayed.

## CVE intelligence

Use `/cve connected` to enable live intelligence, or `/cve offline` to use cached records. The selection persists for subsequent tasks; new installations default to offline. The CLI also accepts `argo agent 'Audit this project' --intelligence connected`.

In connected mode, security tasks inspect project technologies and resolved dependencies before coordination. Argo queries OSV for exact public package versions, uses NVD for known runtime CPE candidates and advisory detail, and adds EPSS/CISA KEV context. Only derived public package/version tuples, CVE IDs and CPEs go to these fixed services. Sources remain in the configured model/workspace flow.

The coordinator can inspect candidates, give up to three at a time to one or all local reviewers, and run bounded Python/Node controls. Findings retain advisory sources, each model's applicability assessment, prerequisites, proposed tests and actual test evidence. A version match or model agreement remains a suspected finding; it is not proof of exploitability.

Supported dependency inputs include npm lockfiles, Yarn v1, uv, Poetry and exact requirements.txt pins. Unsupported formats, private registries/scopes, unpinned runtimes, inconsistent manifests and incomplete queries produce coverage gaps. Lockfile versions are not proof of what is deployed. The on-demand cache has a 24-hour freshness window and exposes stale/missing results; it is not a full local CVE database mirror.

## External MCP

    argo mcp-tools

Public DeepWiki is enabled with a fixed repository-name enum. --no-mcp disables it. Additional public Streamable HTTP MCP servers need an operator-selected endpoint, tool allowlist and argument schemas, through --mcp-profile or /mcp. Calls run in a separate broker container with public DNS/IP checks and no project mount. MCP responses cannot change model, mount or permission settings.

Authenticated/stdio MCP is not implemented. Coding-provider authentication is separate and uses Hush. The [CVE MCP sidecar contract](config/intelligence.contract.json) remains disabled; the native CVE integration above works independently of it.

## Security labs and legacy audits


This owned SQLite lab asks the models to create a failing regression, apply a parameterized-query fix and rerun unchanged tests. A separate container checks positive, missing, apostrophe, injection and data-integrity cases. Model-generated tests alone are not independent security proof.

The legacy engagement workflow adds authorization binding, source/dependency inventory, isolated Semgrep/Gitleaks, typed vulnerability intelligence and bounded authorized HTTP checks:

    uv run python scripts/install_scanners.py
    argo demo --scanners
    argo init engagement.json --id my-audit --repo /absolute/path/to/project
    argo plan engagement.json
    argo authorize engagement.json --operator your-name --reference internal-audit-request
    argo run engagement.json --scanners

Add --origin to initialization for a selected staging origin and --active-web for bounded CORS/Git exposure checks. Authorization binds the exact normalized configuration and expires by default after four hours. It records the operator's authorization, not proof of ownership. Discoveries never expand scope automatically.

TUI /new, /open, /scope, /authorize, /run, /demo, /findings and /retest retain this workflow. CLI run/status/report/verify/stop/retest commands remain available. Add --state-dir before the subcommand to select another evidence directory.

## Boundaries and verification

The selected project is intentionally writable and visible to generated code. This is a development container, not a malware-analysis VM. General network scanning, authenticated business-logic testing, cloud-account access and Nuclei/ZAP workers are not enabled. Legacy HTTP checks use a separate scoped native broker.

Static and model findings remain suspected until deterministic validation. Secret redaction is pattern-based, and local evidence hashes are not signed attestations. The adapters accept compatible protocols, not every proprietary vendor extension. Models must follow the requested JSON/tool contract; availability and task quality remain endpoint-dependent.

    uv run ruff check src tests scripts
    uv run python scripts/validate_design.py
    uv run pytest -q
    uv build

Tests include real Docker workers/scanners, HTTP protocol fixtures, credential-process boundaries and TUI interaction. Actual model validation is separate and recorded in [validation.md](docs/validation.md). Use -m 'not live' when Docker is unavailable.

- [Architecture](docs/architecture.md)
- [Runtime and model settings](docs/isolated-agent.md)
- [Research and original posts](docs/research.md)
- [Roadmap](docs/roadmap.md)
- [Draft engagement example](config/engagement.example.json)
- [Engagement schema](schemas/engagement.schema.json)

Argo is MIT licensed. Models, scanners/rules and external services retain their upstream terms.
