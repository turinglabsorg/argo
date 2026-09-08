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

## September 7: dynamic context, compaction and model visibility

The full local suite passed **121 tests**, including provider HTTP contracts, Hush worker error classification, Docker mounts, source batching, partial local-model output, narrow/wide TUI interaction, preservation on cancellation/checkpoint failure and persisted compaction. Compaction integration exercises two successive checkpoints in one run. No user project was replayed during validation.

Authenticated OpenRouter metadata for meta/muse-spark-1.3-contributor reported context_length **1,048,576** and top_provider.max_completion_tokens **943,718**. Requesting almost the entire advertised completion allowance returned upstream_provider_shared_pool HTTP 429 with Retry-After 60; a 2,048-token diagnostic and the final adaptive 32,768-token initial request both succeeded. Argo now uses the full context window while scaling the initial output request, retaining the advertised ceiling for growth on truncation. This observed rate limit is not proof of what caused an older, generically logged failure.

An actual Muse compaction test used an unsaved 16,384-token profile override to exercise the threshold on synthetic history. It reduced approximately **26,897 to 337 estimated tokens**, preserving the task and recent result. The operator's saved profile remains automatic and reads the million-token window from the API.

Live mounted repair run **6320518f378c4c959806896e0b10cf3b** used Muse with automatic limits and a temporary calculator project. The unchanged regression failed, code.edit ran once, and pytest then passed. A fresh independent container also passed the original test. Evidence integrity was verified. The affected user project OmniPass was not rerun or modified by this validation.

Both installed specialists were exercised through the TUI against a synthetic parameterized SQLite query. Foundation-Sec emitted **14** live updates and VulnLLM **15**. Successful structured responses verify streaming and display; they do not validate findings. In particular, Foundation-Sec reported a suspected SQL injection against this parameterized negative control, so the output must remain a hypothesis. All roles are visible in the header, and F3 exposes their responses. Welcome and Models layouts were checked at 140x44 and 80x24.

![Terminal welcome](assets/welcome.svg)

![Model roles](assets/model-roster.svg)

Limits: token usage is estimated, not counted by the exact model tokenizer. Auto-compaction is within a run; summaries persist, but new tasks do not automatically import prior conversation memory. File snapshot, transport, execution time and local-memory bounds are separate from the selected model's context capacity.

## Streaming reasoning and recorded findings

The full local suite passed **138 tests**, including HTTP-to-Docker findings registration, unknown-evidence and missing-path rejection, native reasoning delivered before the final answer, bounded truncation retry, malformed/incomplete streams, cancellation and legacy findings recovery. Follow-up TUI/registration checks passed **19 tests** after adjusting table column widths; actual saved runs were inspected at 140x44 and 80x24.

A live Foundation-Sec source review rendered native reasoning in a headless Textual session before the final JSON answer, with 598 reasoning updates and 355 answer updates across the review. A separate run completed both installed local specialists. Native thinking support does not guarantee reasoning on every prompt, and the installed VulnLLM artifact does not advertise it.

An explicitly authorized local TypeScript backend audit inspected 123 files with offline scanners, passed 60 existing integration tests, and reproduced six targeted security behaviors using copied source, temporary MongoDB, and simulated storage/email boundaries. Static scanner alerts and model conclusions were triaged separately. One Foundation-Sec prompt missed an ownership defect that the integration test demonstrated; VulnLLM described an incorrect traversal condition. These checks validate the integration and the stated test cases, not broad security accuracy. Customer source, keys, reports and screenshots remain outside this repository.


## Qwen3.8 and simultaneous local reviews

The final regression suite passed **156 tests** and the source distribution/wheel built successfully. Tests include three concurrent HTTP requests, one-reviewer failure, cancellation during silent loading/reasoning, independent result persistence, retained evidence after partial completion, interleaved TUI states, output tail following with preserved manual scrolling, and verified installer-cache reuse.

The new local alias `argo-qwen:27b` uses the [Heretic ARA variant](https://huggingface.co/trohrbaugh/Qwen3.8-27B-heretic-ara) from the linked comparison, via mradermacher's checksum-pinned Q4_K_M GGUF. Native Ollama 0.33.3 reports qwen35 architecture, 27.3B parameters, thinking/tools/completion support and 262,144 maximum context tokens. Argo serves this reviewer at 32,768 context tokens to leave memory for the other models and applications.

An initial import exhausted disk space during Ollama's temporary compatibility validation. Reusing the verified source blob without its duplicate download completed successfully. The installer now checks conversion space and can reuse checksum-verified source blobs; no installed model was removed.

On the 64 GiB Apple Silicon Mac, Qwen alone completed four owned executable controls through the TUI in **287.65 seconds**, with **722 reasoning updates** and **204 answer updates**. It identified the two planted defects (SQL injection and missing object ownership) and correctly described the two fixed controls. Foundation-Sec and VulnLLM also recognized both defects without flagging the fixed controls; Foundation duplicated its two observations. These four tiny cases do not establish broader security accuracy.

Actual Argo run **f92408b3acee4d15a322eb3ae839c197** used the operator's Muse Spark/OpenRouter profile with Hush-backed authentication. Muse selected `security.review_all`, the three local models reviewed the same four-file snapshot, and Muse then synthesized their results. All three returned valid responses. Six suspected observations were saved (three opinions on the same two defects); there were no coverage gaps, no file changes, and the evidence manifest verified.

The three response intervals overlapped for **28.43 seconds**. Native Ollama reported all three models fully GPU-offloaded, with **32.44 GB aggregate model GPU allocation**: Qwen 19.22 GB, Foundation-Sec 7.30 GB and VulnLLM 5.91 GB. System swap usage remained at its pre-existing **171.62 MB** throughout the sampled run. Completed models were subsequently unloaded by Ollama's idle timer.

The full coordinated run took **1,016.14 seconds** (about 17 minutes); Qwen produced **3,310 reasoning updates**, more than its initial standalone trial. This validates concurrent operation and memory fit under the measured configuration, not a speedup. Output lengths and stochastic reasoning differ between trials, and TUI/coordination time is included. Live captures and detailed measurements remain in the operator's private evaluation directory.

## Project CVE intelligence and Node controls — September 7

The final full suite passed 168 tests. Ruff, structural design validation and source/wheel builds passed.

The new integration exercises real local HTTP fixtures for OSV pagination/detail, NVD/EPSS/KEV enrichment, freshness/cache reuse, malformed data, private package exclusion, all three reviewer request payloads, coordinator tool selection, test evidence and persisted Findings. Fixtures return controlled model/advisory responses; they are not paid inference or an accuracy evaluation. TUI checks persist /cve mode at 80 columns. Docker checks execute passing/failing Node controls, deny root writes and Docker socket access, and read large lockfiles through bounded manifest access.

A separate live read-only inventory of an authorized private Node project resolved 615 entries and queried 609 public package versions. OSV returned 125 package/advisory candidates; EPSS and KEV were retrieved from their actual services. Those counts are candidates, not proven vulnerabilities. Coverage includes non-exact runtime tags, excluded private/custom scopes and manifest/lock consistency limitations. Private source, responses and customer evaluation artifacts remain outside the repository.

The Node-enabled worker was rebuilt and executed successfully; the installed image digest is sha256:e8a1ffcf6d500cf2d955b1f6e908edafe0592ccc8527b703d1f19786ff1afa0f. It preserves the offline workspace boundary. Runtime exploit validation and model quality remain separate from a successful advisory lookup.

A separate owned fixture loaded the real jsonwebtoken 8.5.1 dependency in the offline worker. Three deterministic Node controls passed: the missing-key verifier accepted an unsigned identity, an explicitly keyed HS256 verifier rejected that input, and the protected verifier accepted a valid signed identity. This establishes the stated fixture behavior, not exploitability in the customer project. The coordinator/reviewer integration above used HTTP fixtures; these controls were independently executed.

## Foundation-Sec generation recovery

A local four-file TypeScript review reproduced two independent limits in the adapter. The original five-minute inference deadline interrupted active generation. Raising that deadline alone still failed: temperature-zero generation consumed 4,096 tokens and then 8,192 tokens on the truncation retry, producing no final answer. Those attempts took 287.05 and 660.74 seconds respectively.

The same source, prompt, schema, context and output allowances completed at temperature 0.3 in 177.31 seconds, with 2,448 generated tokens and a normal `stop` reason. Reasoning appeared before the answer: 733 reasoning updates and 153 answer updates were observed. The [official model card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning) uses temperature 0.3 for its evaluations. This is a single prompt comparison with a warm cache on the successful call, not a general performance or reliability benchmark.

Foundation-Sec now uses temperature 0.3, a 1,200-second per-inference deadline and the existing four-hour task allowance for longer reviewers. Its 120-second idle timeout, cancellation checks, token/context limits, response size bound and strict final JSON validation remain intact. Other model configurations are unchanged. HTTP regressions exercise slow active responses, hard deadline rejection, cancellation, sampling across truncation retries and controller evidence persistence beyond the old task deadline. The model produced unsupported observations on the repaired source; successful inference does not establish finding accuracy. Detailed customer-source evidence remains in private evaluation storage.

## Bounded source-review recovery

The September 8 full suite passed **194 tests**, including HTTP and Docker integration tests for source subdivision after exhausted output allowances, exact character preservation, fragment line ranges, successful-batch retention, bounded permanent failure, cancellation, and one transient transport retry. Failed reviews preserve partial evidence and remain insufficient to satisfy a required specialist review. Mounted-workspace tests also distinguish redacted evidence from actual source edits: an unchanged audit can complete, while an edited workspace whose export changes under redaction remains incomplete. Ruff, design validation and source/wheel builds passed. These controlled tests validate recovery behavior; actual model review results are recorded separately and do not establish exploitability.

A real Argo run coordinated by the operator-selected OpenRouter GLM profile completed six previously unreviewed TypeScript test files through Foundation-Sec in 789 seconds. One output-limited request completed after its expanded-budget retry; adaptive subdivision was verified by controlled HTTP tests and was not needed in this live run. A deterministic final check verified all six tool-evidence paths and unchanged project source hashes, while evidence-manifest verification passed. Source-fragment hashes describe redacted segments and must not be compared directly with original whole-file hashes. The model's remaining test-code observations stayed suspected; no production vulnerability was confirmed or repaired by this source-review pass. Customer-source reports and detailed evidence remain private.

## Mandatory finding verification

### Verified repair lifecycle

The subsequent full suite passed **300 tests** after live-evaluation hardening. New offline Python and Node executions established original assertion failure, passing positive/negative controls, an implementation change, then all three unchanged tests passing. Denial cases covered missing reproduction, altered roles, test/helper changes, new test configuration, unchanged implementation and failing controls. Further source edits made the verified fix stale. An HTTP-fixture coordinator attempted premature completion, then completed the full repair and persisted recoverable before/after evidence. These protocol fixtures exercise controller behavior, not the quality of a live model.

The installed-project adapter was tested for fixed Vitest arguments, nonempty success, empty/skipped/failed reports, failed-suite completion denial and lockfile mutations above the normal source-snapshot limit. The TUI displayed `fixed` and original failure evidence at both 80 and 140 columns. Ruff, design validation and source/wheel builds passed; the wheel included the worker, finding collector and verification modules. Separately, the real Omnipass Vitest baseline ran through `project.tests` in the offline worker with an ephemeral MongoDB: **419/419 passed**, unchanged application source, no test skips. Its integration setup was adapted before the baseline to use the operator-selected fixture, and Linux dependencies were installed from the frozen lockfile outside the agent runtime.

A live GLM attempt exposed flattened CommonJS output that registered no real tests; the finding adapter kept it inconclusive and the run was cancelled without an accepted repair. Subsequent HTTP/worker checks rejected flattened files and explicit process termination, recovered valid code through bounded coder retries, and verified syntax without executing source. Additional real Node cases distinguished nested assertion failures from setup and mixed runtime errors. The failed live attempt remains an evaluation failure, not evidence of successful autonomous repair. Subsequent checks covered numeric and typed transient errors inside HTTP-success streams, non-retryable authentication/billing/rate-limit events, OpenRouter parameter-support routing, and an executed edit using explicitly selected context while retaining a 1,048,576-token advertised model capacity.

Code output also accepts a line array for each file while retaining the existing content-string format. HTTP and real Node execution verified preserved newlines, comments and executable test registration. MongoDB controls exercised `test.database.reset` through an HTTP-fixture coordinator: the same insert/find probe saw empty data before and after reset, and project files stayed identical. Reset without operator selection was rejected. A further targeted database run passed all four tests in 13.94 seconds, including cleanup after a failed restart.

Real Node tests that kept the event loop open or exceeded the output limit returned exit 124, retained bounded partial output and remained inconclusive. Both worker instances then successfully executed a normal control, verifying cleanup and continued availability. An Omnipass retest timeout remained a failed evaluation; the same unchanged regression passed in a separate fresh worker in 1.20 seconds. Its root cause remains unconfirmed. The new capture behavior preserves failure evidence for explicit coordinator recovery without declaring partial output successful.

A focused live GLM evaluation subsequently recorded an actual `fixed` finding: Argo executed the failing regression and passing controls against the real audit helper and MongoDB, made the two-line implementation repair, reset the fixture and reran all original tests unchanged. Its separate dedicated Node suite passed **31/31**. The native suite exceeded the former two-minute budget, so that repair run remains failed overall. A new Argo task on the same unchanged workspace completed the native suite: first **418/419**, then **419/419** after its one permitted fixture reset/retry. Operator validation linked the original failure, passing retest, current source/test hashes and successful suite across the two preserved runs. A further independent fresh-worker check reproduced failure against original source and success against the exact patch with unchanged tests. The hypothesis and focused instructions were operator-supplied; this is not an autonomous discovery or general reliability benchmark.

The earlier single native-test failure is unclassified because the adapter then retained only counts/logs. It now includes bounded failing test names and assertion/setup messages, preserves execution-limit output and gives the complete installed suite five minutes. A real worker contract rejects apparent success with excess output and exposes actual assertion diagnostics. The 31 Node controls and 419 Vitest tests are separate executions. After applying the reviewed service patch and unchanged controls to the actual local project, its 31 Node controls, all 419 native tests and TypeScript checking also passed. Detailed customer evidence stays private; production proxy topology and other possible vulnerabilities remain outside this proof. Redacted report snapshots were not used as deployable source.

The September 8 suite passed **225 tests**, including 20 targeted finding-verification checks. Real offline workers exercised Python and Node ownership controls against both defective and protected implementations. The HTTP-fixture coordinator generated tests, encountered the premature-completion gate, executed separate controls/regressions and persisted the correct reproduced/refuted interpretations. Other checks rejected contradictory or cross-finding evidence, stale hashes, test-induced source changes, absent source, duplicate test roles, empty/skipped tests and import/runtime failures. Test helpers participate in invalidation; adding unrelated dedicated test files preserves existing results. Imports-only coder output was rejected and repaired before writing. Pending implementation edits were rejected, explicit blockers remained incomplete, evidence reconstruction retained the result, and the TUI displayed verdicts/test paths at both terminal widths. The controller queue also survived a real HTTP-backed context compaction during a fixture run.

Ruff, design validation and source/wheel builds passed. The rebuilt worker matches its recorded source checksum; distribution checks include `finding_validation.py` and the immutable `finding_pytest.py` collector. These fixtures validate orchestration and outcome handling. They do not prove that arbitrary model-written tests are relevant or complete, and do not retroactively validate earlier customer findings.
# OpenRouter prompt cache validation — September 8, 2026

The local suite passed 259 tests in 164.72 seconds; Ruff, design checks and source/wheel builds passed. The wheel includes `provider_usage.py`. Coverage includes final streaming usage chunks, JSON responses, Anthropic input accounting, missing/malformed counters, origin-scoped session headers, the credential child, failed-attempt accounting, retries and actual Docker-backed report persistence. These contract fixtures are separate from paid-provider checks.

Twelve real GLM 5.3 Flash requests compared six requests without an explicit session against six with a stable session, using a synthetic repeated reference and a changing final instruction. Both groups recorded five cache hits after the first request and reused 99.7% of input tokens in those five responses. Different upstream providers served the groups, so latency/cost differences do not establish a session-induced improvement. A separate preliminary sample recorded an intermittent miss. No provider was forced and normal context/output limits were preserved.

Actual Argo run `b77cee838368436dac3cf5f3d13fe11b` read two isolated synthetic files, preserved their contents, completed independent checks and verified all 11 evidence records. Its three coordinator responses recorded 0, 2,560 and 13,440 cached tokens; the last response reused 91.9% of its input, with 49.0% reuse across the growing conversation. An earlier run on a different upstream recorded zero hits; its operator-written validation callback also used an incorrect result key and left the run failed. That original report is retained. These short checks establish working instrumentation and observed cache reuse, not a production-wide hit rate. Historical dashboard activity was unavailable with the inference-only credential.

## Mandatory Qwen finding and fix reviews — September 8, 2026

The full suite passed **321 tests in 403.13 seconds**. Ruff, design validation and source/wheel builds passed. Real offline Python/Node workers and HTTP-fixture models exercised automatic finding/fix reviews, original-source delivery, unchanged before/after regressions, premature-finish rejection and conclusive verdicts. The coordinator receives validated Qwen assessments with its verdict results. Protocol fixtures also cover disagreement, missing context, malformed/incomplete/length-limited responses, authentication failure, source mutation during review, cancellation and exact-context reuse. Changed claims invalidate prior verdicts; deferral preserves source scope and cannot authorize an unreviewed repair. Manual source reviews cannot replace a bound mandatory review.

Both phases survive evidence recovery and appear in Findings at 80x24 and 140x44. Saved model activity displays the assessment without echoing the source prompt. Native reasoning reaches live callbacks and is excluded from stored evidence. Generic source-review batching, provider context budgets and no-finding coding tasks retain their existing behavior. These fixtures establish orchestration and rejection behavior; actual model quality is evaluated separately.

Actual Argo run `6934c7bc8c554220b319276cc08a1254` completed in **1,354.88 seconds** with OpenRouter GLM 5.3 Flash coordinating/coding and local Qwen3.8 27B reviewing both phases automatically. For an operator-supplied ownership-check hypothesis, GLM authored seven real pytest cases in three separate control/regression files. Four control cases passed and three cross-owner regression cases initially failed. Qwen accepted the scoped reproduction, GLM repaired the implementation, and all seven unchanged tests passed. Qwen then accepted the before/after fix assessment; the full seven-test suite passed and the run finished complete. Both reviews and test/source hashes passed evidence-integrity verification.

A separate operator-written 20-case identity matrix and the original tests were executed in fresh workers against the exact before/after source, matched to Argo's recorded hashes. Original source failed; repaired source passed. This checks the owned synthetic helper only, not customer source, deployment behavior or general reviewer reliability. The final coordinator-assessment forwarding and detailed UI additions were covered by protocol/TUI fixtures after the live process had started. The earlier Omnipass repair is not retroactively assigned a Qwen review.

## Project-sized audit and review budgets — September 8, 2026

The complete updated suite passed **330 tests in 312.48 seconds**. HTTP fixtures verify preservation of large lockfiles and complete before/after contexts, growth only within architecture-specific Ollama capacity, rejection before generation when metadata is missing/invalid or capacity is insufficient, and unchanged mandatory-review gates. Docker controller tests read a 26-file project to completion beyond the former 24-step baseline and independently confirm that an explicit two-step cap remains strict. The long-source streaming fixture now advertises the installed Qwen artifact's actual capacity; separate fixtures cover conservative fallback rejection.

The local Ollama API reported `general.architecture: qwen35` and `qwen35.context_length: 262144`. A capacity-only preflight using Omnipass's actual audit service, model, application entrypoint, original controls and complete manifests selected 131,072 tokens for a single snapshot and 196,608 for both snapshots. This calculation is not a model inference, verdict, memory measurement or retrospective Qwen approval. Small prompts retain the original allocation. The full Omnipass audit runs separately and its unfinished findings must not be described as verified fixes.
