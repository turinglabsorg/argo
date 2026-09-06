# Implementation plan

An executable MVP now covers the Textual TUI, core CLI, authorization binding, source audit, isolated Semgrep/Gitleaks, typed provider clients, local cybersecurity model adapters, a scoped HTTP broker, controlled validation, evidence manifests, reports, and retests. The milestone descriptions below remain the full target; they must not be read as a claim that every acceptance criterion has shipped.

Remaining work includes third-party MCP sidecar activation, network-enabled Nuclei/ZAP workers, authenticated API role matrices, general network discovery, restart/recovery hardening, more lockfile formats, and the larger held-out model evaluation corpus. The first real engagement still requires an operator-selected target.

## M0 — Deterministic foundation

Build the CLI, engagement loader, canonical scope digest, typed action contracts, state machine, and local evidence store. Use Python 3.12+ with `uv`, Pydantic, SQLite, and an explicit execution supervisor. Create the dependency lockfile when dependencies are selected.

Implemented CLI surface: `argo` (interactive TUI), `argo tui`, `argo doctor`, `argo init`, `argo plan`, `argo authorize`, `argo run`, `argo runs`, `argo status`, `argo stop`, `argo report`, `argo verify`, `argo retest`, and `argo demo`.

Acceptance:

- Draft, expired, changed, or missing authorizations cannot execute target actions.
- Planning shows targets, test classes, disclosure policy, and limits without contacting targets.
- Unknown action types/fields, unauthorized paths, shell metacharacter arguments, symlink escapes, and invalid credential bindings fail closed.
- A fake adapter proves state persistence, bounded output, deadlines, cancellation, restart, and budget enforcement end to end.
- `doctor` distinguishes installed software from reachable services and usable model artifacts.

## M1 — Useful offline repository audit

Add repository snapshots, exact dependency inventory, pinned local Semgrep rules, and redacted Gitleaks findings. Implement normalized findings and Markdown/JSON reports before adding a model.

Acceptance:

- One fixture repository contains a known positive, a fixed negative control, and a synthetic secret marker.
- Detected findings point to the correct file/range and scanner rule; resolved dependency versions are preserved.
- The secret marker never appears in logs, reports, databases, or proposed model inputs.
- No install scripts, repository hooks, or target network requests execute.
- Scanner errors and unsupported lockfiles appear as coverage gaps rather than clean results.

## M2 — Local analyst and current intelligence

Build the Ollama structured-output adapter, model artifact registry, restricted CVE MCP integration, and typed intelligence records. Evaluate model candidates before selecting defaults. Add OSV correlation from resolved package tuples.

Acceptance:

- Recorded NVD/EPSS/KEV/OSV fixtures exercise successful, missing, stale, malformed, timeout, and rate-limited responses.
- MCP startup/tool discovery matches the pinned contract. Unknown or changed tool schemas prevent readiness.
- Offline mode produces zero outbound provider requests; connected mode exposes only explicitly permitted data.
- Source-injected instructions and malicious MCP/HTML text cannot change tools, target scope, credentials, or budgets.
- Invalid model output is bounded and fails visibly; no silent cloud fallback is possible.
- The full fixture audit produces an evidence-linked explanation with affected-version reasoning and explicit uncertainty.

## M3 — Isolated web/API testing and validation

Implement the Docker worker boundary, enforcing HTTP broker, target relay for local labs, HTTP/TLS adapters, curated Nuclei checks, and ZAP baseline. Create a deliberately vulnerable local fixture service and a fixed variant. Add integration tests whenever backend endpoints or adapter functions are introduced.

Acceptance:

- Requests to a second origin, excluded route, unauthorized method, unapproved redirect, rebinding address, metadata endpoint, Ollama port, and host management service are denied at connection/request time.
- Packet capture or gateway logs demonstrate that workers have no alternate egress route.
- Aggregate target budgets include retries, redirects, crawling, and concurrent workers.
- A seeded defect is reproduced against the vulnerable fixture and absent in the fixed control.
- Cancellation revokes network access and stops descendants; a controller crash does not leave an unbounded scanner.
- The report separates confirmed findings, hypotheses, rejected findings, and incomplete checks.

Complete one vertical demo across M0–M3 before expanding the tool catalog.

## M4 — First operator-selected staging engagement

Configure a real target provided by the operator. Add authenticated API testing using named test-account credentials and an explicit role/object authorization matrix. Add the restricted Nmap connect adapter only after its independent IP/port network boundary passes integration tests.

Acceptance:

- Scope authorization is recorded once; all subsequent actions stay within it.
- Login/test credentials cannot be attached to another origin or leak into model context and evidence.
- A retest reruns the minimum confirming check after a fix and records before/after evidence.
- The report documents tested roles, routes, versions, exclusions, failed checks, and actual coverage.
- No report is posted externally and no production change is applied automatically.

## Evaluation corpus

Create at least 30 labeled cases before choosing the default model: 10 positive/fixed code pairs or cases, 8 dependency applicability cases, 6 hostile-input cases, and 6 web/API authorization or scope cases. Include TypeScript/JavaScript, Python, vulnerable and fixed versions, irrelevant CVEs, and unavailable intelligence. Reserve a held-out subset; record all prompts, templates, artifact hashes, and settings.

Measure precision, recall, false positives on fixed controls, action-schema success, supported evidence references, and reproducibility of confirmed findings. Separately measure wall-clock latency, memory pressure, and CPU/GPU usage on the Mac. Compare a deterministic scanner-only baseline, a general local instruct model, and each specialist. A larger model wins only if it improves useful verified outcomes enough to justify its measured footprint.

Proposed release gates: zero scope or secret-disclosure violations in the boundary suite; all confirmed findings backed by executable fixture evidence; at least 90% precision on the labeled finding set; at least 95% valid structured proposals; and honest coverage reporting for every unavailable component. These are targets, not achieved scores.

## Deferred decisions

- Broader held-out model evaluation: artifacts are now pinned and smoke-tested; release accuracy gates remain unmeasured.
- First real repository/domain, test accounts, and engagement window: supplied for M4; no current infrastructure is implicitly in scope.
- Shodan, VirusTotal, GreyNoise, remote models, and additional providers: add only for a concrete workflow and explicit disclosure policy.
- Browser-driven authenticated flows, smart-contract audits, cloud posture audits, and unrestricted custom PoCs: separate adapters and evaluation tracks.
- A browser dashboard, ACP server for external frontends such as Toad, and packaging as an agent skill remain future work. The native Textual TUI is implemented; see DESIGN.md.
