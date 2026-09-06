# Argo

A local agent for evidence-based security audits and authorized penetration tests.

Argo will combine repository analysis, scoped web/API testing, local language models, and current vulnerability intelligence. It is designed for an Apple Silicon Mac, with scanner workloads isolated from the host.

**Status: design repository.** The architecture, engagement contract, integration contract, and implementation backlog are defined. The agent runtime, scanners, model inference, and sandbox are not implemented or installed by this repository yet. No target has been selected or scanned.

## Intended workflow

1. Define an engagement: repositories, exact web origins, permitted network ranges, credentials by reference, test classes, and limits.
2. Inspect source and dependencies; collect scoped HTTP/TLS observations when enabled.
3. Correlate findings with current CVE, EPSS, and CISA KEV information.
4. Ask local models to explain evidence and propose the next permitted test.
5. Validate each hypothesis with a reproducible check and a negative control.
6. Produce a technical report, evidence bundle, remediation guidance, and retest results.

Authorization is recorded once for the agreed engagement. Its permitted actions can proceed autonomously within that scope; changing the scope creates a new revision.

## Design decisions

| Area | Initial direction |
| --- | --- |
| Controller | Python 3.12+, `uv`, typed action contracts, explicit state machine |
| Inference | Native Ollama on macOS; one model loaded at a time |
| Model candidates | Foundation-Sec-8B-Reasoning for analysis; VulnLLM-R-7B for source review |
| Execution | Disposable ARM64 Docker workers behind an enforced network boundary |
| Intelligence | A restricted adapter around a pinned `cve-mcp-server` revision |
| Persistence | Per-engagement SQLite state plus redacted evidence files |
| Credentials | Hush references; injection only into the component that needs them |
| Interface | CLI first; a dashboard can follow after the workflow is proven |

Specialized models are candidates, not validated autonomous operators. The controller owns execution and scope enforcement.

## Read the design

- [Architecture and execution model](docs/architecture.md)
- [Research: the two posts, source checks, and hardware](docs/research.md)
- [Implementation milestones and acceptance criteria](docs/roadmap.md)
- [Draft engagement example](config/engagement.example.json)
- [Engagement JSON Schema](schemas/engagement.schema.json)
- [Pinned intelligence integration contract](config/intelligence.contract.json)

The example engagement is deliberately `draft`. Its example paths and `.invalid` origin are placeholders, not targets or authorization. JSON Schema validates structure only; the runtime must implement the semantic and network checks described in the architecture.

Validate the design contracts and local document links:

```bash
uv run --no-project --with 'jsonschema[format]==4.25.1' python scripts/validate_design.py
```

This utility checks the schema, sample configuration, and invalid-input fixtures. It does not run the agent or scan a target.

## Initial delivery target

One complete local demonstration: inspect a fixture repository, identify a vulnerable dependency and a seeded code defect, enrich the dependency from a recorded intelligence fixture, verify the code defect in an isolated lab, and produce a report with evidence. Follow with a separately configured staging web/API engagement.

Argo's own code and documents are MIT licensed. Model weights, scanner rules, and third-party services retain their upstream licenses and terms; they are not bundled here.
