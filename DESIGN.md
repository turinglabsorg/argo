# Argo terminal design

## Direction

A quiet field console for security work: a conversation on the left and a compact case file on the right. Evidence and authorization remain visible while the analyst works. Use Textual (MIT) for layout, input, scrolling, keyboard navigation, workers, and headless UI tests.

Reference: the local OpenCode design system at `~/.claude/design-systems/design-md/opencode.ai/DESIGN.md`. Adapt its flat surfaces, monospace rhythm, warm dark palette, and restrained borders to terminal cells. This is an original interface built on Textual; no code is copied from OpenCode or Toad.

## Tokens

| Role | Value |
| --- | --- |
| Background | `#201d1d` |
| Raised surface | `#292525` |
| Input surface | `#302c2c` |
| Text | `#fdfcfc` |
| Secondary text | `#b4abaa` |
| Border | `#514a49` |
| Focus / Argo identity | `#83cec6` |
| Pending / suspected | `#efbb73` |
| Confirmed / failure | `#f28e85` |
| Completed | `#a9c794` |

Inherit the user's terminal monospace font. Do not download fonts or images. Use bold for speaker names and headings. Status must always have a text label, never color alone. Render untrusted strings literally; disable markup and terminal control sequences.

## Layout and interaction

- Brand bar names all three model roles. Keep the selected coder, Foundation-Sec and VulnLLM visible at both terminal widths, with compact labels when space is limited.
- Conversation occupies the flexible left column. Use distinct speaker labels and whitespace, not a box around every message.
- A 34-cell case sidebar shows scope, authorization, models, and run status. Hide below 100 columns; `/scope` remains available.
- Conversation, Models, Findings, and Runs tabs separate work, model activity and saved evidence. F3 or /models opens the model roster; F2 continues to configure the coder.
- A bottom input accepts prose and explicit slash commands. Tab completes commands; up/down recall in-memory prompt history. Enter submits. Escape requests cancellation. Ctrl+L focuses input. Ctrl+Q exits after stopping any active task.
- First launch shows a five-line ASCII ARGO wordmark in the existing teal accent, a short security-and-coding description, and essential shortcuts. Keep the whole introduction readable at 80x24. Remove the agent-demo command from the TUI, CLI, help and current command documentation.
- Show each model's role, identity, availability and current activity. Stream the user-facing summaries and findings of local reviews into named conversation messages and the Models tab. Clearly label partial output as provisional and final security findings as suspected. Never display raw thinking fields or claim that an available model has participated before it is called.
- Findings use a table and a detail pane showing provenance, evidence identifiers, and remediation. Selecting a finding supplies context for the next chat question.
- Plain text starts the isolated agent. Show its current tool/model and keep the offline code boundary visible. `/chat` is explicitly advisory. Tool calls cannot alter scope, MCP policy or host access.
- The launch directory is mounted read/write by default; display its path and direct-write status. `/workspace PATH` changes the selected directory. `/isolated` selects a disposable copy, while `/import` copies sources into that mode. `/diff` shows the changes already made. Resuming a report never mounts a path from that report automatically.
- `/model` and F2 open coding settings: saved profile, protocol (Ollama, OpenAI-compatible, Anthropic-compatible), base URL, model ID, optional Hush credential name, JSON mode and optional context/output token overrides. Blank limits mean API-driven budgets. F3 shows the limit source, estimated input use and auto-compaction count; completed compactions appear in the conversation. Discover models or enter any model ID. Save applies to subsequent coding and coordination calls and persists globally. Keep the current workspace unchanged when switching models. Use a scrollable form with fixed Save/Cancel controls on narrow terminals.
- Keep terminal interaction responsive with background workers. Stream chat output, expose current audit stage, and preserve completed reports under the existing private run directory.
- Model settings show only profile, connection, endpoint, model and credential name by default. Use short labels, generous horizontal padding and a blank row between field groups. Keep profile naming, JSON mode, the API token field and token overrides inside a collapsed Advanced section. Show OpenAI-specific controls only for compatible connections and the discovered-model selector only after discovery. Remove persistent explanatory paragraphs; show concise feedback only after an action. Save and Cancel stay fixed outside the scroll area at both terminal widths.
- Test at 140×44 and 80×24 cells with Textual Pilot, including the welcome screen, all model roles, live analysis, form submission, cancellation and resume.

## Open-source choice

Textual fits the existing Python controller without a second agent runtime. Toad is a ready-made ACP client under AGPL; adding an ACP server can be evaluated later. The initial TUI uses Argo's typed controller directly.
