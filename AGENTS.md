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
