# Isolated agent runtime

The default TUI interaction and `argo agent` implement an actual tool loop. The coordinator chooses one action and its arguments, the controller validates them, a reviewed adapter executes it, and the next model turn receives the observed result. Assistant action messages and observed results remain in a bounded conversational history, with a compact record of completed tools. The separate coder receives the original operator requirements, current edit instruction, selected source and recent test feedback. It stops on completion, cancellation, failure, or a bounded action/deadline budget. This is distinct from the legacy deterministic engagement audit.

## Models and tools

| Role / tool | Implementation |
| --- | --- |
| Coordinator | Local `argo-coder:30b-a3b`; `--planner` can explicitly select either installed specialist |
| Coder | Local `argo-coder:30b-a3b`, a separate schema-constrained call producing complete files |
| Security review | Local `argo-foundation-sec:8b` or `argo-vulnllm:7b`; findings remain suspected |
| `workspace.list`, `workspace.read` | Bounded relative-path text access inside the container |
| `code.edit` | Coder may modify only the requested relative paths |
| `python.run` | Fixed Python executable, selected workspace script, no shell or command-line arguments |
| `python.tests` | Fixed `python -m pytest -q -p no:cacheprovider` invocation |
| `bandit.scan` | Fixed recursive Bandit JSON scan, excluding the tests directory |
| `mcp.TOOL` | Discovered remote tool intersected with operator policy and server argument schema |
| `finish` | Returns a summary; changed workspaces require a successful pytest run against unchanged file contents |

Python's standard library, pytest 8.4.2 and Bandit 1.8.6 are installed. No general shell tool is exposed; generated Python can launch subprocesses inside the same offline container and its resource limits. Network package downloads, authenticated browser workflows and non-Python test runners are not available. The coder can produce other text files, but the current execution toolchain is Python. Cloud coders are not configured; source stays in local inference.

## Execution boundary

The native trusted controller alone talks to Docker and loopback Ollama. Generated code and project tests run inside a Docker Desktop Linux container with:

- No bind mounts or volumes; `/workspace` and `/tmp` are private tmpfs filesystems.
- `--network none`, including no access to Ollama, the host, metadata services or public targets.
- User/group `65532`, read-only root, dropped capabilities, default seccomp, no new privileges and private process namespaces.
- 768 MiB memory including swap, two CPUs, 64 processes, 256 MiB workspace and 64 MiB temporary storage.
- A 50-second execution budget and bounded stdout/stderr. Cancellation or adapter timeout removes the entire container, including detached descendants.

All adapter code is baked into an image built from a pinned Python base and hash-locked dependencies. `scripts/install_worker.py` records the built image's content digest in `~/.argo/worker.json`; execution uses that digest, not a mutable tag. No secrets, environment files or source checkout are copied into the image build context. Rebuild after changing worker code.

This boundary relies on Docker Desktop, its VM and the host kernel. It is not intended for malware or container-escape research. Normal completion, cancellation and handled errors remove the container. Abrupt controller or machine failure may leave an Argo-labelled container; inspect and remove that specific container before resuming. Saved tasks restart from verified files, never by replaying unknown external side effects.

## Imports, output and continuation

The operator can explicitly import one project directory. The controller reads selected text formats through the existing bounded source inventory, excludes secret/configuration and dependency directories, rejects symlinks and hard-linked/nonregular files, and redacts recognized secrets. Redaction is pattern-based and may alter source behavior; it is not a complete secret detector. Home and filesystem root are rejected. The model cannot choose host paths or import another directory.

Workspace paths must be visible relative paths without traversal, hidden components or control characters. Reads and writes walk directory descriptors with `O_NOFOLLOW`; exports accept bounded regular UTF-8 files only. Limits are 100 files, 96 KiB per file, 2 MiB aggregate, and 6 MiB serialized workspace. Oversized imports fail visibly.

Each run exports a `code/` tree and unified `changes.diff` under its private run directory. The model cannot select a host output location or apply changes to original projects. Reports and tool records are redacted. A workspace snapshot is stored as hashed evidence; `--continue RUN_ID` and TUI `/resume RUN_ID` validate it and seed a fresh offline container. TUI follow-up tasks continue the last workspace; `/reset` starts empty. Arbitrary process or interpreter state is not restored.

## External MCP

Remote calls execute in a separate immutable container with no code workspace or host mounts. Its reviewed adapter supports HTTPS Streamable HTTP, initialization, JSON-RPC responses, JSON and SSE transport, session headers, tool discovery and tool calls. It never executes server-initiated callbacks, sampling requests, prompts, local commands or resources. Redirects are rejected. DNS answers must all be public; a validated address is pinned for the TLS connection with hostname verification. Responses, requests, pagination and elapsed time are bounded.

The broker has Docker bridge networking, but accepts only the reviewed MCP protocol operation. Generated code never runs in it. The application-level endpoint policy does not claim to be a general-purpose firewall for arbitrary code.

The default [DeepWiki server](https://docs.devin.ai/work-with-devin/deepwiki-mcp) needs no authentication. Only `read_wiki_structure` is exposed, and its `repoName` argument must be one of `python/cpython`, `pallets/flask`, `psf/requests`, or `pytest-dev/pytest`. Thus default MCP calls cannot upload source or arbitrary text. Model responses from MCP are untrusted evidence, not instructions.

Use `argo mcp-tools` to verify discovery. `argo agent TASK --no-mcp` disables outbound MCP calls. An additional public server can be selected with `--mcp-profile FILE` or TUI `/mcp FILE`. Example:

```json
{
  "name": "deepwiki",
  "endpoint": "https://mcp.deepwiki.com/mcp",
  "tools": [{
    "name": "read_wiki_structure",
    "arguments": {
      "type": "object",
      "properties": {"repoName": {"const": "python/cpython"}},
      "required": ["repoName"],
      "additionalProperties": false
    }
  }]
}
```

The operator profile is the disclosure and action boundary. Every call must pass both its schema and the discovered server schema. Only explicitly listed tools are available; tool annotations cannot grant permissions. Schema references and regex constraints are rejected to avoid external resolution and untrusted regex execution in the controller. Prefer enums and constants for identifiers. A profile accepting arbitrary strings can disclose those strings to its server. No automatic profile expansion, authenticated MCP, local stdio servers, or secret-bearing URLs are supported. MCP failure is recorded as a coverage gap; it does not silently enable another provider.

## Evidence and confidence

`report.json` records `kind: isolated_agent`, status, model roles, tool evidence references, summary, coverage gaps, workspace evidence, and artifact paths. `report.md`, `state.sqlite` and the standard evidence manifest support inspection with existing run/report/verify commands. An action failure or missing test runner cannot be reported as a successful test. Reaching the action budget yields `incomplete`.

Model reviews and generated regression tests are not independent proof of security. The owned SQL demo separately validates the generated implementation with deterministic positive, negative, injection and data-integrity checks. The wider held-out accuracy evaluation remains future work.
