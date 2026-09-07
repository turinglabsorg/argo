import getpass
import json
import shlex
import threading
import time
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from argo.advisories import load_mode, save_mode
from argo.agent import import_sources, restore, run_agent
from argo.agent_findings import load_agent_findings
from argo.agent_models import ANALYST, QWEN, REVIEWER, SPECIALISTS
from argo.chat import answer, display_text
from argo.context_budget import ModelLimits
from argo.contracts import Actions, Engagement, Scope
from argo.controller import Cancelled, run
from argo.evidence import clean, read_evidence, read_state
from argo.mcp import default_profile, load_profile
from argo.model_activity import analysis_text
from argo.model_dialog import ModelDialog
from argo.providers import SETTINGS, load_settings, model_limits
from argo.scope import authorize, check_authorization, digest, load, normalize, save
from argo.services import CYBER_MODELS, demo, doctor, run_path
from argo.workspace import project_directory

COMMANDS = [
    "/cve",
    "/workspace",
    "/test-db",
    "/isolated",
    "/agent",
    "/models",
    "/chat",
    "/import",
    "/reset",
    "/diff",
    "/mcp",
    "/new",
    "/open",
    "/scope",
    "/authorize",
    "/run",
    "/retest",
    "/demo",
    "/findings",
    "/runs",
    "/resume",
    "/report",
    "/evidence",
    "/model",
    "/doctor",
    "/stop",
    "/help",
    "/quit",
]
HELP = """Project agent      Type a task, or /agent TASK
CVE intelligence   /cve connected | offline (no argument: status)
Coding model       /model or F2 (local / OpenAI / Anthropic)
All models         /models or F3 (roles, activity and live responses)
Mounted project    /workspace [PATH]
Test database      /test-db [mongodb | off]
Disposable mode    /isolated
Import project     /import /path/to/project
Fresh workspace    /reset
Review code diff   /diff
MCP configuration  /mcp [on | off | /path/to/profile.json]
Advisory chat      /chat QUESTION

Create a case      /new
Open a case        /open /path/to/engagement.json
Review scope       /scope
Authorize scope    /authorize
Start audit        /run [--no-model] [--no-scanners]
Isolated lab       /demo [--no-model] [--no-scanners]
Retest case        /retest [--no-model] [--no-scanners]
Browse findings    /findings
Browse past runs   /runs
Open a past run    /resume RUN_ID
Read report        /report
Inspect evidence   /evidence [EVIDENCE_ID]
Chat model         /model foundation | vulnllm
Service readiness  /doctor
Cancel work        /stop or Escape

Plain text starts the agent in an offline Docker container. It can create and change code,
run Python, pytest and Bandit, and consult approved MCP tools through a separate broker.
The launch directory is mounted read/write: changes go directly into your project.
/isolated selects a disposable workspace. /import copies sources into that mode.
/model chooses the coding endpoint and model. /diff shows changes already made.
Tab completes commands. Up/down recall prompts. Reports and code are saved locally."""

LOGO = r"""    _    ____   ____  ___
   / \  |  _ \ / ___|/ _ \
  / _ \ | |_) | |  _| | | |
 / ___ \|  _ <| |_| | |_| |
/_/   \_\_| \_\\____|\___/"""


class Prompt(Input):
    BINDINGS = [
        Binding("up", "recall(-1)", show=False),
        Binding("down", "recall(1)", show=False),
        Binding("tab", "complete", show=False),
    ]

    def __init__(self):
        super().__init__(
            placeholder="Describe what you want to investigate or change…", id="prompt", max_length=8000
        )
        self.history = []
        self.position = 0
        self.draft = ""

    def remember(self, value):
        self.history = [*self.history[-99:], display_text(value)]
        self.position = len(self.history)
        self.draft = ""

    def action_recall(self, direction):
        if not self.history:
            return
        if self.position == len(self.history):
            self.draft = self.value
        self.position = max(0, min(len(self.history), self.position + direction))
        self.value = self.history[self.position] if self.position < len(self.history) else self.draft
        self.cursor_position = len(self.value)

    def action_complete(self):
        matches = (
            [command for command in COMMANDS if command.startswith(self.value)]
            if self.value.startswith("/")
            else []
        )
        if matches:
            self.value = matches[0] + " "
            self.cursor_position = len(self.value)
        else:
            self.screen.focus_next()


class NewCase(ModalScreen):
    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("NEW AUDIT", classes="dialog-title")
            yield Label("Engagement file")
            yield Input(str(Path.cwd() / "argo.engagement.json"), id="case-file")
            yield Label("Case ID")
            yield Input("local-audit", id="case-id")
            yield Label("Repository directory (optional)")
            yield Input(str(Path.cwd()), id="case-repo")
            yield Label("Exact web origin (optional)")
            yield Input(placeholder="https://staging.example.com", id="case-origin")
            yield Checkbox("Enable bounded active web checks", id="case-active")
            yield Static("", id="form-error", markup=False)
            with Horizontal(classes="dialog-actions"):
                yield Button("Create draft", variant="primary", id="create")
                yield Button("Cancel", id="dismiss")

    @on(Button.Pressed)
    def clicked(self, event):
        if event.button.id == "dismiss":
            self.dismiss(None)
            return
        try:
            target = Path(self.query_one("#case-file", Input).value).expanduser().absolute()
            if target.exists() or target.is_symlink():
                raise ValueError("Engagement file already exists. Use /open to load it.")
            repo = self.query_one("#case-repo", Input).value.strip()
            origin = self.query_one("#case-origin", Input).value.strip()
            engagement = normalize(
                Engagement(
                    id=self.query_one("#case-id", Input).value.strip(),
                    purpose="Authorized security audit",
                    scope=Scope(repositories=[repo] if repo else [], web_origins=[origin] if origin else []),
                    actions=Actions(
                        local_audit=bool(repo),
                        web_observe=bool(origin),
                        web_validate=self.query_one("#case-active", Checkbox).value,
                    ),
                )
            )
            save(target, engagement)
            self.dismiss(target)
        except Exception as exc:
            self.query_one("#form-error", Static).update(display_text(str(exc))[:400])


class AuthorizeCase(ModalScreen):
    def __init__(self, engagement):
        super().__init__()
        self.engagement = engagement

    def compose(self) -> ComposeResult:
        with Vertical(id="authorization-dialog"):
            yield Label("AUTHORIZE THIS SCOPE", classes="dialog-title")
            yield TextArea(
                json.dumps(clean(self.engagement.model_dump()), indent=2),
                read_only=True,
                id="authorization-scope",
            )
            yield Label("Operator")
            yield Input(getpass.getuser(), id="operator")
            yield Label("Authorization reference / reason")
            yield Input(
                placeholder="Owned repository, engagement reference, or written permission", id="reference"
            )
            yield Static("Valid for 4 hours. Any scope change requires a new authorization.", classes="muted")
            with Horizontal(classes="dialog-actions"):
                yield Button("Authorize displayed scope", variant="primary", id="approve")
                yield Button("Cancel", id="dismiss")

    @on(Button.Pressed)
    def clicked(self, event):
        if event.button.id == "dismiss":
            self.dismiss(None)
        else:
            operator = self.query_one("#operator", Input).value.strip()
            reference = self.query_one("#reference", Input).value.strip()
            if not operator or not reference:
                self.notify("Enter the operator and authorization reference", severity="warning")
                return
            self.dismiss((operator, reference, digest(self.engagement)))


class ReportScreen(ModalScreen):
    def __init__(self, path, content=None):
        super().__init__()
        self.path = path
        self.content = content

    def compose(self) -> ComposeResult:
        with Vertical(id="report-dialog"):
            yield Label("EVIDENCE" if self.content else "AUDIT REPORT", classes="dialog-title")
            yield Static(display_text(str(self.path)), markup=False, classes="muted")
            yield TextArea(
                display_text(self.content if self.content is not None else self.path.read_text())[:500000],
                read_only=True,
                id="report-content",
            )
            yield Button("Close", id="dismiss")

    @on(Button.Pressed)
    def close_report(self):
        self.dismiss(None)


class ArgoApp(App):
    TITLE = "Argo · Security console"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("ctrl+q", "leave", "Quit", priority=True),
        Binding("escape", "stop", "Stop", priority=True),
        Binding("ctrl+l", "prompt", "Prompt", priority=True),
        Binding("f1", "help", "Help"),
        Binding("ctrl+r", "runs", "Runs", priority=True),
        Binding("f2", "coding_model", "Model", priority=True),
        Binding("f3", "models", "Models", priority=True),
    ]
    CSS_PATH = "data/tui.tcss"

    def __init__(self, state_root: Path, engagement_path: Path | None = None, *, project=..., settings_path=SETTINGS):
        super().__init__()
        self.state_root = state_root
        self.intelligence_path = state_root.parent / "intelligence-settings.json"
        self.engagement_path = engagement_path
        self.engagement = None
        self.report_data = None
        self.current_run = None
        self.selected_finding = None
        self.model = CYBER_MODELS[0]
        self.history = []
        self.busy = False
        self.leaving = False
        self.cancel_event = threading.Event()
        self.transcript = []
        self.streaming = None
        self.ready_models = set()
        self.ollama_status = "checking"
        self.agent_seed = {}
        self.agent_profile = default_profile()
        self.agent_mcp = True
        self.test_database = "off"
        self.project = Path.cwd().resolve() if project is ... else project
        self.settings_path = settings_path
        self.coding = load_settings(settings_path).coding
        self.model_activity = {}
        self.model_messages = {}
        self.active_model = None
        self.coding_limits = None

    def ui(self, selector, widget_type):
        return self.screen_stack[0].query_one(selector, widget_type)

    def compose(self) -> ComposeResult:
        yield Static(
            "  ARGO  /  security & code",
            id="brand",
            markup=False,
        )
        yield Static("", id="model-roster", markup=False)
        with Horizontal(id="workspace"):
            with TabbedContent(id="views"):
                with TabPane("Conversation", id="chat-tab"):
                    with VerticalScroll(id="conversation"):
                        yield Static(Text.assemble((LOGO + "\n\n", "bold #83cec6"), ("Review code. Apply fixes. Verify with Python tests.\n", "bold"), ("Describe what you want to investigate or change.\n\n", "#b4abaa"), ("F2 Settings   F3 Models   /workspace Project   /help", "#83cec6")), id="welcome")
                with TabPane("Models", id="models-tab"):
                    with VerticalScroll(id="models-feed"):
                        yield Static("All model roles · live responses from local analysis", classes="muted")
                        for role in ("coding", *SPECIALISTS):
                            with Vertical(classes="model-card"):
                                yield Static("", id=role + "-identity", classes="model-identity", markup=False)
                                yield Static("", id=role + "-activity", classes="model-state", markup=False)
                                yield TextArea("No response yet.", read_only=True, id=role + "-output", classes="model-output", soft_wrap=True)
                with TabPane("Findings", id="findings-tab"):
                    yield DataTable(id="findings", cursor_type="row", zebra_stripes=True)
                    yield TextArea(
                        "Select a finding to inspect its evidence and remediation.",
                        read_only=True,
                        id="finding-detail",
                    )
                with TabPane("Runs", id="runs-tab"):
                    yield DataTable(id="runs", cursor_type="row", zebra_stripes=True)
                    yield Static(
                        "Enter on a run to load its report. /retest starts a new run for the loaded engagement.",
                        classes="muted",
                    )
            with VerticalScroll(id="sidebar"):
                yield Static("PROJECT", classes="sidebar-title")
                yield Static("", id="project-summary", markup=False)
                yield Button("Coding model · F2", id="coding-settings")
                yield Static("CASE FILE", classes="sidebar-title")
                yield Static("No engagement loaded", id="scope-summary", markup=False)
                yield Button("New audit", id="new-audit")
                yield Static("MODELS", classes="sidebar-title")
                yield Static("Foundation-Sec · 8B\nChecking local models…", id="model-summary", markup=False)
                yield Button("All models · F3", id="all-models")
                yield Static("ACTIVITY", classes="sidebar-title")
                yield Static("Ready", id="activity", markup=False)
                yield Button("Run audit", id="run-audit", variant="primary")
                yield Button("Stop", id="stop-audit", disabled=True)
                yield Static(
                    "/workspace  Project folder\n/diff       Review changes\n/runs       Saved results\n/help       All commands",
                    classes="sidebar-help",
                    markup=False,
                )
        yield Static("Ready · /model selects coding · /workspace shows the project", id="status", markup=False)
        yield Prompt()
        yield Footer()

    async def on_mount(self):
        self.ui("#findings", DataTable).add_columns("State", "Severity", "Finding", "Location")
        self.ui("#runs", DataTable).add_columns("Created", "Case", "Status", "Findings", "Run ID")
        if self.engagement_path:
            self.open_case(self.engagement_path)
        self.refresh_runs()
        self.refresh_case()
        self.refresh_models()
        self.check_services()
        self.check_model_limits(self.coding)
        self.action_prompt()
        self.set_interval(1, self.refresh_model_wait)

    def on_resize(self, event):
        self.set_class(event.size.width < 100, "compact")
        self.call_after_refresh(self.layout_findings)

    def say(self, speaker, content):
        content = display_text(content)
        self.transcript.append((speaker, content))
        self.transcript = self.transcript[-200:]
        widget = Static(
            Text.assemble((speaker + "\n", "bold #83cec6" if speaker == "ARGO" else "bold #efbb73"), content),
            classes="message",
        )
        container = self.ui("#conversation", VerticalScroll)
        for old in list(container.children)[:-199]:
            old.remove()
        container.mount(widget)
        self.call_after_refresh(container.scroll_end, animate=False)
        return widget

    def set_status(self, text):
        self.ui("#status", Static).update(display_text(text))
        self.ui("#activity", Static).update(display_text(text))

    def refresh_case(self):
        self.ui("#project-summary", Static).update(display_text(str(self.project) + "\nREAD / WRITE" if self.project else "Disposable workspace\nNo project mounted"))
        if self.engagement:
            engagement = self.engagement
            targets = engagement.scope.repositories + engagement.scope.web_origins
            self.ui("#scope-summary", Static).update(
                display_text(
                    engagement.id
                    + "\n"
                    + engagement.authorization.status.upper()
                    + "\n\n"
                    + "\n".join(targets)
                )
            )
        elif self.report_data:
            details = (
                ("PROJECT RUN\n" if self.report_data.get("project") else "DISPOSABLE RUN\n") + self.report_data["status"].upper()
                + "\n\nType a task to continue.\n/diff reviews changes.\n/reset clears task context."
                if self.report_data.get("kind") == "isolated_agent"
                else self.report_data["engagement_id"]
                + "\nREPORT REVIEW\n\nOpen an engagement to run or retest."
            )
            self.ui("#scope-summary", Static).update(
                display_text(details)
            )
        self.ui("#run-audit", Button).disabled = self.busy or self.engagement is None
        self.ui("#stop-audit", Button).disabled = not self.busy

    def refresh_models(self):
        rows = []
        for role, model, label in self.model_roles():
            local = role != "coding" or self.coding.protocol == "ollama"
            availability = ("Installed locally" if model in self.ready_models else ("Not installed" if self.ollama_status == "ready" else "Ollama " + self.ollama_status)) if local else "Configured endpoint"
            activity = self.model_activity.get(model, {})
            state = activity.get("state", "Not used in this run")
            stage = activity.get("stage", "")
            status = state + (" · " + stage if stage else "")
            title = self.model_label(model)
            rows.append(label.upper() + "\n" + title + "\n" + status)
            if role == "coding" and self.coding_limits:
                status += f"\nContext: {self.coding_limits.context_window:,} tokens · Output ceiling: {self.coding.max_tokens or self.coding_limits.max_output_tokens or 'automatic'}\n{self.coding_limits.source}"
                if activity.get("context"):
                    context = activity["context"]
                    status += f"\nInput estimate: {context['estimated_input_tokens']:,} tokens · Auto-compacts: {context['compactions']}"
            self.ui("#" + role + "-identity", Static).update(display_text(label.upper() + "  /  " + title + "\n" + model))
            self.ui("#" + role + "-activity", Static).update(display_text(availability + " · " + status))
            output = self.ui("#" + role + "-output", TextArea)
            output.set_class(not (activity.get("text") or activity.get("reasoning")), "empty-output")
            text = display_text("\n\n".join(filter(None, ["Reasoning\n" + activity["reasoning"] if activity.get("reasoning") else "", activity.get("text")])) or activity.get("waiting") or "Called when needed by the task. No response yet.")
            if output.text != text:
                offset = output.scroll_y
                follow = offset >= output.max_scroll_y - 1
                output.load_text(text)
                if follow:
                    self.call_after_refresh(output.scroll_end, animate=False, immediate=True)
                else:
                    self.call_after_refresh(output.scroll_to, y=offset, animate=False, immediate=True)
        self.ui("#model-summary", Static).update(display_text("\n\n".join(rows)))
        self.ui("#model-roster", Static).update(display_text("  " + "  /  ".join(self.model_label(model) for _, model, _ in self.model_roles())))

    def model_roles(self):
        return [("coding", self.coding.model, "Coding & coordination"), ("foundation", ANALYST, "Security analysis"), ("vulnllm", REVIEWER, "Vulnerability review"), ("qwen", QWEN, "Deep review · experimental")]

    def model_label(self, model):
        return {ANALYST: "Foundation-Sec 8B", REVIEWER: "VulnLLM-R 7B", QWEN: "Qwen3.8 27B", "meta/muse-spark-1.3-contributor": "Muse Spark 1.3 Contributor"}.get(model, model.rsplit("/", 1)[-1])

    @work(thread=True, exit_on_error=False)
    def check_model_limits(self, profile):
        limits = model_limits(profile)
        self.call_from_thread(self.limits_result, profile, limits)

    def limits_result(self, profile, limits):
        if profile == self.coding:
            self.coding_limits = limits
            self.refresh_models()

    @work(thread=True, exit_on_error=False)
    def check_services(self):
        status = doctor()
        self.call_from_thread(self.service_result, status)

    def service_result(self, status):
        self.ready_models = {m["name"] for m in status["ollama"].get("local_models", [])}
        self.ollama_status = status["ollama"].get("status", "unavailable")
        self.refresh_models()

    def open_case(self, path):
        try:
            self.engagement = load(Path(path).expanduser())
            self.engagement_path = Path(path).expanduser().absolute()
            self.history = []
            self.report_data = None
            self.selected_finding = None
            self.current_run = None
            self.refresh_findings()
            self.refresh_case()
            self.say("ARGO", f"Loaded {self.engagement.id}. Use /scope to review targets and actions.")
        except Exception as exc:
            self.say("ERROR", str(exc))

    def new_case_result(self, path):
        if path:
            self.open_case(path)
            self.say("ARGO", "Draft saved. Review /scope, then /authorize before running it.")
        self.action_prompt()

    def authorize_result(self, result):
        if not result:
            return
        try:
            operator, reference, reviewed_digest = result
            config = load(self.engagement_path)
            if digest(config) != reviewed_digest:
                raise ValueError("Scope changed while the dialog was open. Review it again.")
            self.engagement = authorize(config, operator, reference)
            save(self.engagement_path, self.engagement)
            self.refresh_case()
            self.say("ARGO", "Authorization recorded for the displayed scope. /run starts the audit.")
        except Exception as exc:
            self.say("ERROR", str(exc))
        self.action_prompt()

    @on(Input.Submitted, "#prompt")
    def submitted(self, event):
        prompt = event.value.strip()
        if not prompt:
            return
        self.ui("#prompt", Prompt).remember(prompt)
        self.ui("#prompt", Prompt).value = ""
        self.dispatch(prompt)

    def dispatch(self, prompt):
        if prompt == "/stop":
            self.action_stop()
            return
        if prompt == "/quit":
            self.action_leave()
            return
        if self.busy:
            self.say("ARGO", "Work is in progress. Escape or /stop requests cancellation.")
            return
        self.ui("#views", TabbedContent).active = "chat-tab"
        self.say("YOU", prompt)
        if not prompt.startswith("/"):
            self.start_agent(display_text(prompt))
            return
        try:
            parts = shlex.split(prompt)
            command, args = parts[0], parts[1:]
            if command == "/help":
                self.action_help()
            elif command == "/models" and not args:
                self.action_models()
            elif command == "/cve" and len(args) <= 1:
                if args:
                    save_mode(args[0], self.intelligence_path)
                mode = load_mode(self.intelligence_path)
                self.say("ARGO", "CVE intelligence: " + mode + (". OSV, NVD, EPSS and KEV; public package versions and CVE/CPE identifiers only." if mode == "connected" else ". Cached records only; missing or stale coverage is reported."))
            elif command == "/model" and not args:
                self.action_coding_model()
            elif command == "/workspace" and len(args) <= 1:
                if args:
                    self.project = project_directory(args[0])
                    self.agent_seed = {}
                self.refresh_case()
                self.say("ARGO", f"Mounted read/write for the next task: {self.project}" if self.project else "Disposable workspace. /workspace PATH selects a project.")
            elif command == "/test-db" and len(args) <= 1:
                if args:
                    if args[0] not in {"off", "mongodb"}:
                        raise ValueError("Use /test-db mongodb or /test-db off")
                    self.test_database = args[0]
                self.say("ARGO", "Test database: " + self.test_database + (" · temporary, worker loopback only" if self.test_database == "mongodb" else ""))
            elif command == "/isolated" and not args:
                self.project = None
                self.agent_seed = {}
                self.refresh_case()
                self.say("ARGO", "The next task uses a disposable workspace. No project is mounted.")
            elif command == "/chat" and args:
                self.start_chat(prompt[len("/chat "):])
            elif command == "/agent" and args:
                self.start_agent(prompt[len("/agent "):])
            elif command == "/import" and len(args) == 1:
                self.begin("Copying selected project sources")
                self.import_project(Path(args[0]))
            elif command == "/reset" and not args:
                self.agent_seed = {}
                self.say("ARGO", "Task context reset. The selected project is unchanged." if self.project else "The next task starts with an empty disposable workspace.")
            elif command == "/diff" and not args:
                if not self.current_run or not (self.current_run / "changes.diff").is_file():
                    raise ValueError("Run or resume an isolated agent task first.")
                self.push_screen(ReportScreen(self.current_run / "changes.diff"))
            elif command == "/mcp" and len(args) <= 1:
                if args and args[0] in {"on", "off"}:
                    self.agent_mcp = args[0] == "on"
                elif args:
                    self.agent_profile = load_profile(Path(args[0]).expanduser())
                    self.agent_mcp = True
                self.say("ARGO", json.dumps({"enabled": self.agent_mcp, "profile": self.agent_profile.model_dump()}, indent=2))
            elif command == "/new":
                self.push_screen(NewCase(), self.new_case_result)
            elif command == "/open" and len(args) == 1:
                self.open_case(Path(args[0]))
            elif command in {"/scope", "/authorize"}:
                if not self.engagement_path:
                    raise ValueError("Create or open an engagement first: /new or /open FILE")
                self.engagement = load(self.engagement_path)
                self.refresh_case()
                if command == "/scope":
                    self.say("ARGO", json.dumps(clean(self.engagement.model_dump()), indent=2))
                else:
                    self.push_screen(AuthorizeCase(self.engagement), self.authorize_result)
            elif command in {"/run", "/demo", "/retest"}:
                if set(args) - {"--no-model", "--no-scanners"}:
                    raise ValueError("Available flags: --no-model, --no-scanners")
                if command != "/demo":
                    if not self.engagement_path:
                        raise ValueError("Create or open an engagement first: /new or /open FILE")
                    self.engagement = load(self.engagement_path)
                    check_authorization(self.engagement)
                previous = self.current_run if command == "/retest" else None
                if command == "/retest" and not previous:
                    raise ValueError("Load a previous run with /resume RUN_ID first")
                self.begin("Starting " + command[1:])
                self.audit(
                    command,
                    [] if "--no-model" in args else CYBER_MODELS,
                    "--no-scanners" not in args,
                    previous,
                )
            elif command == "/findings":
                self.ui("#views", TabbedContent).active = "findings-tab"
            elif command == "/runs":
                self.action_runs()
            elif command == "/resume" and len(args) == 1:
                self.resume(args[0])
            elif command == "/report":
                if not self.current_run or not (self.current_run / "report.md").is_file():
                    raise ValueError("No report loaded. Select a completed run with /runs.")
                self.push_screen(ReportScreen(self.current_run / "report.md"))
            elif command == "/evidence" and len(args) <= 1:
                if not self.current_run or not self.report_data:
                    raise ValueError("Select a completed run first: /runs")
                identities = {
                    identity for item in self.report_data["findings"] for identity in item["evidence_ids"]
                }
                default_identity = (self.selected_finding or {}).get("evidence_ids", [None])[0]
                if self.report_data.get("kind") == "isolated_agent":
                    records = [item["evidence_id"] for item in self.report_data.get("tools", [])]
                    identities.update(records)
                    identities.add(self.report_data["workspace_evidence"])
                    default_identity = records[-1] if records else self.report_data["workspace_evidence"]
                identity = args[0] if args else default_identity
                if identity not in identities:
                    raise ValueError("Select a finding or specify one of its evidence IDs")
                evidence = read_evidence(self.current_run, identity)
                self.push_screen(
                    ReportScreen(
                        self.current_run / "evidence" / f"{identity}.json", json.dumps(evidence, indent=2)
                    )
                )
            elif command == "/model" and len(args) == 1 and args[0] in {"foundation", "vulnllm"}:
                self.model = CYBER_MODELS[args[0] == "vulnllm"]
                self.refresh_models()
                self.check_services()
                self.say("ARGO", "Chat model: " + self.model)
            elif command == "/doctor":
                self.begin("Checking local services")
                self.show_doctor()
            else:
                raise ValueError("Unknown command or invalid arguments. /help lists supported commands.")
        except Exception as exc:
            self.say("ERROR", str(exc))

    def begin(self, status):
        self.model_activity = {}
        self.model_messages = {}
        self.active_model = None
        self.busy = True
        self.cancel_event.clear()
        self.set_status(status)
        self.refresh_case()
        self.refresh_models()

    def finish(self):
        for activity in self.model_activity.values():
            if activity.get("state") == "Working":
                activity["state"] = "Stopped" if self.cancel_event.is_set() else "Finished"
        self.active_model = None
        self.busy = False
        self.streaming = None
        self.refresh_case()
        self.refresh_models()
        if self.leaving:
            self.exit()
        else:
            self.action_prompt()

    def progress(self, data):
        self.current_run = self.state_root / data["run_id"]
        if "findings" in data and isinstance(data["findings"], list):
            self.report_data = {"run_id": data["run_id"], "findings": data["findings"]}
            self.refresh_findings()
        self.set_status(data["stage"].capitalize() + "  ·  " + data.get("model", data["run_id"][:12]))
        if data.get("compact", {}).get("phase") == "complete":
            compact = data["compact"]
            self.say("ARGO", f"Auto-compact saved: {compact['before_tokens']:,} → {compact['after_tokens']:,} estimated tokens. Latest results and tool evidence retained.")
        if data.get("model"):
            if data.get("limits") and data["model"] == self.coding.model:
                self.coding_limits = ModelLimits.model_validate(data["limits"])
            if data.get("context"):
                self.model_activity.setdefault(data["model"], {})["context"] = data["context"]
            self.model_update(data["model"], data["stage"], data.get("text"), data.get("provisional"), data.get("error", False), data.get("reasoning"), data.get("status"))

    def model_update(self, model, stage, text=None, provisional=None, error=False, reasoning=None, status=None):
        self.active_model = model
        activity = self.model_activity.setdefault(model, {})
        if text is None and reasoning is None and status is None and stage in {"security.review", "analysis"}:
            self.model_messages.pop(model, None)
            self.model_messages.pop((model, "reasoning"), None)
            activity.pop("text", None)
            activity.pop("reasoning", None)
            activity.update(waiting="Loading model", started=time.monotonic())
        activity.update(stage=stage, state="Error" if error else ("Response complete" if provisional is False else "Working"))
        if status:
            activity.update(waiting=status, started=time.monotonic())
        if reasoning:
            activity["reasoning"] = display_text(reasoning)
            activity.pop("waiting", None)
            key = (model, "reasoning")
            if key not in self.model_messages and model in self.model_messages and not activity.get("text"):
                self.model_messages[key] = self.model_messages.pop(model)
            self.render_model_output(key, self.model_label(model) + " · reasoning", activity["reasoning"], "#b4abaa")
        if text:
            activity["text"] = display_text(text)
            activity.pop("waiting", None)
            label = self.model_label(model)
            suffix = " · provisional analysis" if provisional else (" · analysis incomplete" if error else " · response")
            self.render_model_output(model, label + suffix, activity["text"])
        self.refresh_model_wait()
        self.refresh_models()

    def render_model_output(self, key, label, text, color="#83cec6"):
        widget = self.model_messages.get(key)
        if widget is None:
            widget = self.say(label, text)
            widget.transcript_entry = self.transcript[-1]
            self.model_messages[key] = widget
        for index, entry in enumerate(self.transcript):
            if entry is widget.transcript_entry:
                widget.transcript_entry = (label, text)
                self.transcript[index] = widget.transcript_entry
                break
        widget.update(Text.assemble((label + "\n", "bold " + color), (text, color if color != "#83cec6" else "")))
        self.call_after_refresh(self.ui("#conversation", VerticalScroll).scroll_end, animate=False)

    def refresh_model_wait(self):
        for model, activity in self.model_activity.items():
            if activity.get("state") == "Working" and activity.get("waiting"):
                elapsed = int(time.monotonic() - activity["started"])
                self.render_model_output(model, self.model_label(model), f"{activity['waiting']} · {elapsed}s")

    @work(thread=True, exit_on_error=False)
    def audit(self, command, models, scanners, previous):
        try:
            options = {
                "on_progress": lambda data: self.call_from_thread(self.progress, data),
                "cancelled": self.cancel_event.is_set,
            }
            result = (
                demo(self.state_root, models, scanners, **options)
                if command == "/demo"
                else run(
                    self.engagement,
                    self.state_root,
                    models=models,
                    scanners=scanners,
                    retest=previous,
                    **options,
                )
            )
            self.call_from_thread(self.audit_done, result)
        except Exception as exc:
            self.call_from_thread(self.task_failed, display_text(str(exc)))

    def audit_done(self, result):
        self.resume(result["run_id"])
        self.set_status(result["status"].capitalize() + f"  ·  {result['findings']} findings")
        if result.get("demo_validation"):
            self.say("ARGO", result["demo_validation"])
        self.refresh_runs()
        self.finish()

    def task_failed(self, message):
        self.say("ERROR", message)
        self.set_status("Stopped" if self.cancel_event.is_set() else "Failed · see conversation")
        self.finish()

    def start_agent(self, prompt):
        try:
            if self.project is not None:
                self.project = project_directory(self.project)
        except ValueError as exc:
            self.say("ERROR", str(exc))
            return
        self.begin("Starting agent · " + self.coding.model)
        self.agent_work(prompt)

    @work(thread=True, exit_on_error=False)
    def import_project(self, path):
        try:
            files = import_sources(path)
            self.call_from_thread(self.import_done, files)
        except Exception as exc:
            self.call_from_thread(self.task_failed, display_text(str(exc)))

    def import_done(self, files):
        self.project = None
        self.agent_seed = files
        self.say("ARGO", f"Copied {len(files)} sanitized source files. The next task edits only this isolated copy.")
        self.set_status("Project copy ready")
        self.finish()

    @work(thread=True, exit_on_error=False)
    def agent_work(self, prompt):
        try:
            options = {
                "profile": self.agent_profile, "use_mcp": self.agent_mcp,
                "coding": self.coding.model_copy(deep=True),
                "intelligence_mode": load_mode(self.intelligence_path),
                "test_database": self.test_database,
                "cancelled": self.cancel_event.is_set,
                "on_progress": lambda data: self.call_from_thread(self.progress, data),
            }
            result = run_agent(prompt, self.state_root, seed=None if self.project else self.agent_seed, project=self.project, **options)
            self.call_from_thread(self.agent_done, result)
        except Exception as exc:
            self.call_from_thread(self.task_failed, display_text(str(exc)))

    def agent_done(self, result):
        self.resume(result["run_id"])
        self.set_status(result["status"].capitalize() + " · isolated worker removed")
        if result.get("independent_validation"):
            self.say("ARGO", json.dumps(result["independent_validation"], indent=2))
        self.refresh_runs()
        self.finish()

    @work(thread=True, exit_on_error=False)
    def show_doctor(self):
        status = doctor()
        self.call_from_thread(self.service_result, status)
        self.call_from_thread(self.say, "ARGO", json.dumps(status, indent=2))
        self.call_from_thread(self.set_status, "Service check complete")
        self.call_from_thread(self.finish)

    def start_chat(self, prompt):
        context = {"scope": self.engagement.scope.model_dump() if self.engagement else None}
        if self.report_data:
            context.update(
                {
                    "run_id": self.report_data["run_id"],
                    "coverage_gaps": self.report_data["coverage_gaps"],
                    "findings": [self.selected_finding]
                    if self.selected_finding
                    else self.report_data["findings"][:4],
                }
            )
            evidence = []
            for item in context["findings"]:
                for identity in item["evidence_ids"][:2]:
                    try:
                        evidence.append({"id": identity, "record": read_evidence(self.current_run, identity)})
                    except (OSError, ValueError):
                        evidence.append({"id": identity, "status": "unavailable or integrity check failed"})
            context["evidence"] = evidence[:4]
        self.begin("Preparing response · " + self.model_label(self.model))
        self.model_update(self.model, "Advisory response")
        self.streaming = self.say(self.model_label(self.model), "Preparing response…")
        self.chat(prompt, context)

    def check_cancelled(self):
        if self.cancel_event.is_set():
            raise Cancelled("Cancellation requested")

    @work(thread=True, exit_on_error=False)
    def chat(self, prompt, context):
        try:
            response = answer(
                self.model,
                prompt,
                self.history,
                context,
                self.check_cancelled,
                lambda text: self.call_from_thread(self.chat_update, text),
            )
            self.call_from_thread(self.chat_done, prompt, response)
        except Exception as exc:
            self.call_from_thread(self.task_failed, display_text(str(exc)))

    def chat_update(self, text):
        if self.streaming and text:
            self.streaming.update(Text.assemble((self.model_label(self.model) + "\n", "bold #83cec6"), display_text(text)))
            self.model_activity[self.model]["text"] = display_text(text)
            self.refresh_models()
            self.ui("#conversation", VerticalScroll).scroll_end(animate=False)

    def chat_done(self, prompt, response):
        self.chat_update(response)
        self.history = [
            *self.history[-4:],
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": response},
        ]
        self.set_status("Ready · " + self.model)
        self.finish()

    def refresh_findings(self):
        table = self.ui("#findings", DataTable)
        table.clear()
        self.ui("#finding-detail", TextArea).load_text(
            "Select a finding to inspect its evidence and remediation."
        )
        for item in (self.report_data or {}).get("findings", []):
            table.add_row(
                *[
                    Text(display_text(str(value)))
                    for value in (
                        item["status"],
                        item["severity"],
                        item["title"],
                        item["asset"] + (":" + str(item["line"]) if item.get("line") else ""),
                    )
                ],
                key=item["id"],
            )
        self.layout_findings()

    def layout_findings(self):
        if not self.is_running or not self.screen_stack[0].query("#findings"):
            return
        table = self.ui("#findings", DataTable)
        width = table.size.width
        if width < 50 or len(table.columns) != 4:
            return
        location = min(28, width // 3)
        widths = [10, 8, max(12, width - location - 27), location]
        changed = False
        for column, target in zip(table.columns.values(), widths):
            if column.width != target or column.auto_width:
                column.width, column.auto_width = target, False
                changed = True
        if changed:
            table.refresh(layout=True)

    @on(TabbedContent.TabActivated)
    def findings_view_activated(self, event):
        if event.pane.id == "findings-tab":
            self.call_after_refresh(self.layout_findings)

    @on(DataTable.RowHighlighted, "#findings")
    def finding_selected(self, event):
        if not self.is_running or not self.report_data or not self.screen_stack[0].query("#finding-detail"):
            return
        self.selected_finding = next(
            (f for f in self.report_data["findings"] if f["id"] == event.row_key.value), None
        )
        if self.selected_finding:
            item = self.selected_finding
            content = (
                f"{item['title']}\n{item['asset']}" + (f":{item['line']}" if item.get('line') else "")
                + f"\n{item['status'].upper()} · {item['severity']} · {item.get('cwe') or 'No CWE assigned'}\n\n{item['explanation']}\n\nRemediation\n{item['remediation']}\n\nEvidence\n"
                + "\n".join(item["evidence_ids"])
            )
            if item.get("validation"):
                content += "\n\nValidation\n" + item["validation"]
            self.ui("#finding-detail", TextArea).load_text(display_text(content))

    def refresh_runs(self):
        table = self.ui("#runs", DataTable)
        table.clear()
        for path in sorted(self.state_root.glob("*"), key=lambda p: p.name):
            try:
                state = read_state(run_path(self.state_root, path.name))
                if not state.get("finding_count") and (path / "report.json").is_file():
                    report = json.loads((path / "report.json").read_text())
                    state["finding_count"] = len(load_agent_findings(path, report))
                table.add_row(
                    *[
                        Text(display_text(str(state.get(key, "—"))))
                        for key in ("created_at", "engagement_id", "status", "finding_count", "run_id")
                    ],
                    key=path.name,
                )
            except Exception:
                continue

    @on(DataTable.RowSelected, "#runs")
    def run_selected(self, event):
        if not self.busy:
            self.resume(event.row_key.value)

    def resume(self, identity):
        try:
            path = run_path(self.state_root, identity)
            report = json.loads((path / "report.json").read_text())
            report["findings"] = load_agent_findings(path, report)
            if self.current_run != path:
                self.model_activity = {}
                self.model_messages = {}
            analyses = list(report.get("analysis", []))
            for item in report.get("tools", []):
                if item.get("tool") == "security.review":
                    analyses.append(read_evidence(path, item["evidence_id"])["data"]["result"])
            recorded_models = {analysis.get("model") for analysis in analyses}
            for model in SPECIALISTS.values():
                if model not in recorded_models:
                    errors = [gap.removeprefix(model + ": ") for gap in report.get("coverage_gaps", []) if gap.startswith(model + ": ")]
                    if errors:
                        analyses.append({"model": model, "status": "failed", "error": "\n".join(errors)})
            for analysis in analyses:
                if analysis.get("model"):
                    activity = self.model_activity.setdefault(analysis["model"], {})
                    failed = analysis.get("status") == "failed"
                    activity.update(state="Error" if failed else "Saved response", stage="Security analysis", text=analysis.get("error", "") if failed else analysis_text(json.dumps(analysis)))
            self.refresh_models()
            self.report_data = report
            self.current_run = path
            self.history = []
            self.selected_finding = None
            self.refresh_findings()
            self.refresh_case()
            if report.get("kind") == "isolated_agent":
                if report.get("project"):
                    self.agent_seed = {}
                    self.ui("#views", TabbedContent).active = "chat-tab"
                    self.say("ARGO", report["summary"] + f"\n\nChanged project: {report['project']}\nDiff: {path / 'changes.diff'}\nNext task uses the currently selected workspace: {self.project or 'disposable'}.")
                    self.set_status("Reviewing project run " + identity[:12])
                    return
                self.project = None
                self.agent_seed = restore(path)
                self.refresh_case()
                self.ui("#views", TabbedContent).active = "chat-tab"
                self.say("ARGO", report["summary"] + f"\n\nCode: {path / 'code'}\nDiff: {path / 'changes.diff'}\n{len(self.agent_seed)} files restored. Type the next task to continue, or /reset to start empty.")
                self.set_status("Reviewing agent run " + identity[:12])
                return
            self.set_status("Reviewing " + identity[:12] + f" · {len(report['findings'])} findings")
            self.ui("#views", TabbedContent).active = "findings-tab"
            self.say(
                "ARGO",
                f"Loaded run {identity}. {len(report['findings'])} findings.\nReport: {path / 'report.md'}\nUse /report to read it or /chat to discuss a finding. /import copies a selected project for isolated editing.",
            )
        except Exception as exc:
            self.say("ERROR", str(exc))

    @on(Button.Pressed)
    def button_clicked(self, event):
        if event.button.id == "all-models":
            self.action_models()
        elif event.button.id == "coding-settings":
            self.action_coding_model()
        elif event.button.id == "new-audit":
            self.dispatch("/new")
        elif event.button.id == "run-audit":
            self.dispatch("/run")
        elif event.button.id == "stop-audit":
            self.action_stop()

    def action_prompt(self):
        if not isinstance(self.screen, ModalScreen):
            self.ui("#prompt", Input).focus()

    def action_coding_model(self):
        if not self.busy and not isinstance(self.screen, ModalScreen):
            self.push_screen(ModelDialog(self.settings_path), self.coding_selected)

    def action_models(self):
        if not isinstance(self.screen, ModalScreen):
            self.ui("#views", TabbedContent).active = "models-tab"

    def coding_selected(self, profile):
        if profile:
            self.coding = profile
            self.coding_limits = None
            self.check_model_limits(profile)
            self.refresh_models()
            self.say("ARGO", f"Coding and coordination: {profile.model}\n{profile.protocol} · {profile.base_url}\nSaved for subsequent tasks. Project selection is unchanged.")
        self.action_prompt()

    def action_help(self):
        self.ui("#views", TabbedContent).active = "chat-tab"
        self.say("ARGO", HELP)

    def action_runs(self):
        if not isinstance(self.screen, ModalScreen):
            self.refresh_runs()
            self.ui("#views", TabbedContent).active = "runs-tab"

    def action_stop(self):
        if isinstance(self.screen, ModalScreen):
            self.screen.dismiss(None)
        elif self.busy:
            self.cancel_event.set()
            self.set_status("Cancellation requested · waiting for the current operation to stop")

    def action_leave(self):
        if self.busy:
            self.leaving = True
            self.cancel_event.set()
            self.set_status("Stopping work before closing…")
        else:
            self.exit()
