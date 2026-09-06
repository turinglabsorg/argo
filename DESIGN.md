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

- One-line brand bar: ARGO, purpose, and local-only inference.
- Conversation occupies the flexible left column. Use distinct speaker labels and whitespace, not a box around every message.
- A 34-cell case sidebar shows scope, authorization, models, and run status. Hide below 100 columns; `/scope` remains available.
- Chat, Findings, and Runs tabs keep reports and older sessions accessible.
- A bottom input accepts prose and explicit slash commands. Tab completes commands; up/down recall in-memory prompt history. Enter submits. Escape requests cancellation. Ctrl+L focuses input. Ctrl+Q exits after stopping any active task.
- First launch explains natural-language tasks, `/import`, `/diff`, `/agent-demo`, and advisory `/chat`. Legacy `/new` and `/open` manage engagements; authorization displays the exact contract before a separate operator action.
- Findings use a table and a detail pane showing provenance, evidence identifiers, and remediation. Selecting a finding supplies context for the next chat question.
- Plain text starts the isolated agent. Show its current tool/model and keep the offline code boundary visible. `/chat` is explicitly advisory. Tool calls cannot alter scope, MCP policy or host access.
- `/import` copies a selected project; `/diff` previews exported modifications. Agent `/resume` restores verified files for a new container; `/reset` starts empty. Keep these controls distinct from the legacy engagement audit commands.
- Keep terminal interaction responsive with background workers. Stream chat output, expose current audit stage, and preserve completed reports under the existing private run directory.
- Test at 140×44 and 80×24 cells with Textual Pilot, including form submission, cancellation, resume, and the isolated demo.

## Open-source choice

Textual fits the existing Python controller without a second agent runtime. Toad is a ready-made ACP client under AGPL; adding an ACP server can be evaluated later. The initial TUI uses Argo's typed controller directly.
