# Containerized agent runtime

Version 0.3 defaults to direct project editing. The TUI and CLI mount their launch directory read/write at /workspace. The operator can select another directory with /workspace or --project, or use /isolated, --isolated, --import or --continue for disposable mode. Generated code executes inside Docker; the trusted controller communicates with Docker, model endpoints and the separate MCP broker.

## Model selection

F2 or /model opens persistent coding settings. One selected profile supplies both the coordinator and the separate coder call. Local security specialists remain optional adapters. Remote coding does not require Ollama.

| Protocol | Generation | Discovery | Credential |
| --- | --- | --- | --- |
| Ollama | /api/chat, schema-constrained NDJSON | /api/tags | Optional Bearer |
| OpenAI-compatible | /chat/completions, SSE or JSON | /models | Optional Bearer |
| Anthropic-compatible | /messages, SSE or JSON | /models | Optional x-api-key |

HTTP(S) URLs accept custom hosts, ports and proxy prefixes. An empty path defaults to /v1 for compatible APIs. Existing API-root paths are preserved; full generation URLs are accepted. No model-name allowlist or silent provider fallback applies to coding. Manual IDs work when discovery is unsupported.

OpenAI output modes are prompt-only JSON, JSON object and JSON schema. Prompt-only is the broadest default because compatible servers differ in response_format support. The token field can be max_tokens or max_completion_tokens. Anthropic uses a separate system field, merged adjacent turns and anthropic-version 2023-06-01. Responses API-only endpoints and proprietary authentication extensions are not supported by the Chat Completions adapter.

Outputs are parsed and validated against the controller's JSON schema. The reader handles Ollama NDJSON, OpenAI deltas and Anthropic text deltas, rejecting incomplete streams and explicit provider errors. HTTP errors do not expose response bodies. Requests have connection/read deadlines, a 300-second stream budget and a 16 MiB HTTP response bound (the authenticated child output remains bounded at 8 MiB). Generated code and tool output cannot reconfigure providers.

References: [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat), [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create), [Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming).

## Settings and credentials

The controller atomically persists ~/.argo/models.json with private permissions. ModelSettings contains an active profile name and up to 30 uniquely named CodingProfile objects. Each profile contains name, protocol, base_url, model, credential, output_mode, token_parameter, optional max_tokens and optional context_window. The credential field is a Hush secret name, never an API key.

The TUI provides profiles, discovery, an explicit synthetic model test and manual entry. Its main form shows only profile, connection, endpoint, model and credential name. Advanced settings hold profile naming, OpenAI-specific compatibility fields and token overrides. Discovery choices appear only after a successful listing. Save affects subsequent tasks; an active task's profile is immutable. Model selection does not change the project. Settings are global and used by the CLI; explicit --planner retains a local coordinator override.

Authenticated calls invoke hush run --name NAME --env ARGO_PROVIDER_KEY --redact with the fixed argo.provider_worker module. The request arrives over stdin; the key is injected into that native child, removed from its environment after reading, and used only for the selected endpoint. The child returns filtered results and cannot execute model code or arbitrary commands. Neither keys nor the Hush vault enter Docker. Unauthenticated profiles make no credential lookup.

Selecting a remote profile authorizes sending task context and selected source to its endpoint. Source redaction is pattern-based, not complete data-loss prevention. Model tests send a synthetic JSON request without project source.

## Agent loop and tools

The coordinator chooses an action and parameters. The controller validates both the envelope and selected tool schema, executes a reviewed adapter, and retains bounded assistant/action/result turns. The coder receives the original task, edit instruction, selected source and latest test feedback.

| Tool | Behavior |
| --- | --- |
| workspace.list / workspace.read | Bounded relative-path source access |
| code.edit | Selected coder returns complete contents for explicitly named files |
| python.run | Fixed Python executable with one workspace script |
| python.tests | Fixed pytest invocation over the project |
| node.tests | Fixed Node test runner over 1–40 tests/argo-security/*.test.cjs files |
| security.inventory | Technologies, resolved packages, manifest hashes and coverage gaps |
| security.cves | Refresh/reuse inventory-matched advisories; pages of 30 candidates |
| security.advisory | Known candidate detail with CVE-based NVD/EPSS/KEV enrichment |
| security.validation | Attach same-run test evidence and an interpretation to a known CVE candidate |
| bandit.scan | Recursive Bandit scan |
| security.review | One local reviewer: foundation, vulnllm or qwen; optional 1–3 known candidate IDs |
| security.review_all | All three reviewers concurrently on the selected paths and advisory context |
| mcp.TOOL | Remote tool intersected with operator policy |
| finish | Saves the result and code diff |

Python changes require passing pytest against unchanged file contents. Non-Python text edits can complete with a recorded lack of runtime verification. Python 3.12, standard library, pytest, Bandit and a digest-pinned Node.js 22 binary are installed. Node tests use already available project dependencies; npm and network installation are unavailable. Targeted Node controls do not run the full project suite. Other languages still record missing runtime coverage. Generated tests are not independent security proof.

## Project mount

Only an operator-selected canonical directory is mounted. Home and filesystem root are rejected. Models cannot choose another host path, Docker flag or image. Worker inspection checks that exactly one writable bind mount maps the selected project to /workspace. Disposable mode has no bind mounts.

Project mode uses the operator UID/GID; disposable mode uses 65532. Both use offline networking, read-only root, dropped capabilities, no-new-privileges, private process namespaces, default seccomp, 768 MiB memory including swap, two CPUs, 64 processes and bounded /tmp. The project intentionally exposes all its contents to generated Python or Node code, including hidden files. It is not a boundary between files within the project.

The immutable adapter lives in the pinned worker image outside the mount. Model-facing file operations reject traversal, hidden path components, symlinks and hard links, using directory descriptors and O_NOFOLLOW. Edits compare selected files with pre-generation contents before writing; known concurrent changes produce a conflict. This is a best-effort check, not a filesystem transaction or lock against external editors.

Snapshots skip hidden/dependency/build directories, binary/unreadable files and files above 96 KiB. Limits are 1,000 text files in project mode (100 in disposable mode), 2 MiB aggregate and 6 MiB serialized. Oversized snapshots fail visibly. The separate manifests action reads only known manifest/lockfile basenames, with a 2 MiB per-file/aggregate and 100-file limit; this includes lockfiles larger than the source export limit. It preserves descriptor-relative no-follow access and records skipped files. These adapter bounds do not limit executed code to the same files; code can access the whole selected project.

Execution has a 50-second deadline and bounded output. Cancellation removes the container and detached descendants. Already-written project changes remain after cancellation, timeout or test failure. There is no automatic rollback. Abrupt controller failure can leave a container. This is a development container, not a malware-analysis VM.

## Reports and continuation

Each run stores code snapshots, changes.diff, model metadata, tool records, test-file hashes and integrity evidence. Reports retain kind: isolated_agent for compatibility and add project and coding_profile.

Reopening a mounted-project report does not change the selected directory. Report paths never authorize mounts. Disposable snapshots are verified before restoration. --continue always restores into disposable mode; it never overwrites the current project. /reset clears context without reverting files.

The internal SQL validation fixture in agent_demo.py always uses disposable mode and independently verifies generated code in a fresh container. Failing-then-passing unchanged regressions, production changes and independent controls gate its completion.

## External MCP

MCP runs in a separate immutable bridge-network container without the project. Its adapter implements bounded HTTPS Streamable HTTP initialization, sessions, JSON/SSE discovery and calls. It rejects redirects and non-public DNS, pins a validated address for TLS, and never executes server callbacks, sampling or local commands.

Default DeepWiki exposes only read_wiki_structure with four permitted public repositories. Custom public profiles explicitly select endpoint, tools and schemas. Calls must pass both operator and discovered schemas; references and regex constraints are rejected. Responses cannot alter model, mount or permission settings.

Authenticated/stdio MCP and the CVE sidecar remain unimplemented. MCP authentication is separate from coding-provider authentication.

## Model activity and context

The TUI shows coding/coordination, Foundation-Sec, VulnLLM and Qwen3.8 27B as separate roles, with independent activity and live messages during concurrent reviews. F3 or /models opens live output and readiness. Local source-review callbacks publish exposed reasoning separately from provisional summaries/findings. Ollama capabilities are read through /api/show; thinking is enabled only when advertised. Reasoning is transient, sanitized output, never validated evidence or an instruction source. Loading shows elapsed time before output arrives. Completed reviews are read back from verified evidence when reopening a run. The former agent-demo command is removed from the public CLI and TUI; its internal validation module remains for regression checks.

Provider limits are read from model metadata and cached per endpoint, model, credential reference and override for five minutes, with a task-start refresh. OpenRouter context_length/top_provider.context_length and max_completion_tokens are supported, alongside compatible context_window, max_input_tokens and max_output_tokens fields. Ollama /api/show identifies model capacity while the configured runtime uses num_ctx=16384 unless overridden. Unknown endpoint metadata produces a visible 16,384-token fallback. Profile overrides preserve manual support for any compatible endpoint. API failures never cause provider substitution.

The context estimate is serialized UTF-8 bytes divided by three, with framing allowance and 10% context headroom; it is not an exact tokenizer. Automatic output budgets use the advertised output ceiling and remaining context. Initial generation output scales with input size and the model window, bounded by the remaining context and advertised maximum. Truncated inference can grow up to that ceiling over at most four requests, without replaying a tool. HTTP 429 retains Retry-After and identifies the shared upstream pool when advertised; Argo does not retry quota failures or switch providers automatically. Token-limit, filtering, malformed JSON, schema, network and timeout errors remain distinguishable through the Hush child without returning private response bodies.

Coordination retains complete observed results instead of clipping every result to 5,000 characters or taking only eight turns. Source selection follows the model's input budget. Independent worker file, transport and execution limits remain enforced. Specialist reviews split oversized source into bounded batches and aggregate suspected findings; a batch may contain a partial file, which limits cross-file reasoning.

At 90% of its input budget, Conversation summarizes older observations in model-sized fragments, retaining the original operator task and recent observations. Completed tool status comes from the controller's ledger, not from model memory. Summaries are untrusted reference material and cannot grant authorization. A successful compaction persists context_compaction evidence, context.json and report context_compactions IDs. A failed or cancelled summary leaves the original in-memory observations intact. Older records remain in evidence. Compaction happens within a run; new tasks do not automatically import prior run memory.

## Recorded findings

The coordinator uses `findings.record` with source path, optional line, title, severity, explanation, remediation and existing tool evidence IDs. The controller rejects unknown evidence and source paths outside the current workspace. Local specialist responses and structured `python.run` output with a `findings` array also populate the report and live Findings tab. Model/script observations always start as suspected; unspecified severity is shown as info, not inferred severity. Passing static assertion scripts never upgrades a finding to confirmed.

Older agent reports with an empty findings list are reconstructed at read time from content-verified tool records. Supported legacy aliases are `titolo`, `file` and `evidenza`. Free-form final summaries are not parsed into findings, arbitrary evidence citations in tool output are discarded, and invalid paths are ignored. Original reports and manifests are not rewritten. Runs displays the recovered count.

Foundation-Sec and VulnLLM source reviews reserve space for an output increase from 4,096 to 8,192 tokens. A length stop retries only that inference once; errors distinguish truncation, malformed JSON, incomplete streams, HTTP errors, connection failures and timeouts. Their 16,384-token local context, 2 MiB stream budget and 300-second per-request deadline remain independent of the selected coding provider context. Qwen uses the larger local limits below.


## Third reviewer and concurrent reviews

`security.review` accepts `model: qwen` for the pinned Heretic ARA Q4_K_M artifact (`argo-qwen:27b`). This is an experimental general reasoning model, not a model trained specifically for security. Its source-review allocation is 32,768 context tokens and 8,192 initial output tokens, with one truncation-only retry at 16,384. Temperature is 0.6. Each inference has a 3,600-second deadline, a 600-second idle-read limit and an 8 MiB transport bound to accommodate reasoning deltas. These are local serving allocations, not the model's advertised maximum context or the selected coding provider's limits.

`security.review_all` accepts `paths` (1–6 existing relative source paths) and optional `candidate_ids` (1–3 known catalog IDs). Three fixed worker threads call the configured reviewers against the same snapshot; they receive no workspace-writing or execution tools. A bounded queue delivers activity and results back to the controller thread. SQLite and evidence writes remain on that thread. Each completed or failed reviewer receives its own `agent_tool` record under `security.review`; the aggregate result includes `reviews`, `execution: concurrent`, and `status: complete|partial`. Each review carries model, status and evidence_id, plus a validated answer or sanitized error. Failures become coverage gaps; successful findings remain suspected. Cancellation retains already recorded responses and stops the remaining requests.

The local HTTP reader polls cancellation during connection, model loading and silent stream periods every 0.2 seconds, and cancels/closes pending asynchronous requests. The synchronous public review API runs this reader in its own worker event loop. Interleaved TUI updates reuse a message per reviewer and never mark another reviewer finished merely because its peer emits a token.

A task using Qwen or all reviewers expands its overall deadline from 30 minutes to four hours, while keeping per-request and step bounds. Foundation-Sec and VulnLLM retain their 16,384-token contexts and 4,096→8,192 output budgets. Ollama decides whether the models fit in memory together; concurrent dispatch does not prove simultaneous inference. The legacy audit and advisory chat commands retain their two original specialist adapters.

Run the owned SQL-injection and object-ownership controls with:

```sh
uv run python scripts/evaluate_reviewers.py --model qwen --output /tmp/argo-qwen-evaluation
uv run python scripts/evaluate_reviewers.py --model all --output /tmp/argo-parallel-evaluation
```

Use a fresh output directory for each evaluation. `--sequential` provides a serial comparison. The harness executes both vulnerable and fixed controls before inference, saves source hashes, elapsed times and separate model answers, and leaves issue interpretation to a reviewer. It does not score substring matches as security accuracy.

## Inventory, advisory context and runtime evidence

`project_inventory.py` parses npm package-lock/shrinkwrap, Yarn v1, uv.lock, poetry.lock and exact requirements.txt pins. It records source manifests/hashes, direct dependency groups, literal import hints and coverage gaps. pnpm/bun are recognized but not parsed; ranges and unsupported sources are not silently resolved. Unknown scoped npm packages and private/custom registries are excluded from external queries. Known Docker runtime images get CPE candidates only with exact versions. Imports, lockfiles and CPE matches do not establish deployment or reachability.

`advisories.py` uses the native OSV/NVD/EPSS/CISA KEV clients, independently of the disabled external MCP sidecar. Settings persist privately in ~/.argo/intelligence-settings.json. Library calls default to offline; TUI/CLI load the saved mode, with `/cve` and `--intelligence` controls. Connected security tasks perform inventory and lookup before the coordinator request; reviews can also trigger lookup. Manifest fingerprints invalidate the run's catalog.

OSV querybatch requests contain at most 100 exact package tuples and follow up to five pages per query; advisory detail is hydrated separately. Limits are 1,500 inventory entries, 100 advisory records and 200 package/advisory candidates, with explicit truncation gaps. Runtime CPE queries use up to 20 NVD records per technology. Candidate pages show 30 entries; complete evidence is saved. EPSS and KEV enrichment is bounded to 100 CVE IDs. Public origins and request paths are controller-defined. No source text, arbitrary model URL, discovered credential or installation script is sent to intelligence providers.

Each private cache entry retains provider, retrieval time, source and response. Fresh entries are reused for 24 hours. Connected refresh failures can use explicitly stale records; offline mode distinguishes cached, stale and absent data. Malformed, withdrawn, mismatched or incomplete records cannot become a clean negative result. EPSS/KEV are prioritization signals, not project-specific exploitability proof.

Reviews receive up to three known candidate IDs, package/version/source metadata and bounded advisory text inside their existing context budgets. Their schema requires an applicability assessment for every supplied candidate: potentially_applicable, not_applicable or insufficient_context, with reasoning, prerequisites and a local positive/negative test plan. Advisory text is untrusted evidence. Each completed reviewer persists independently and updates its Finding; failed or unreviewed candidates remain coverage gaps.

`security.validation` accepts one known candidate, 1–5 same-run Python/Node test evidence IDs, an interpretation (reproduced, not_reproduced or blocked), and an explanation. Test records must contain actual test hashes; non-blocked interpretations require a passing control run. This records the model's interpretation of observed execution and does not promote the Finding to confirmed. Reports include intelligence inventory/catalog and typed per-model applicability assessments. Subsequent catalog views preserve previous reviews and runtime evidence.
