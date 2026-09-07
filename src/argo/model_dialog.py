from textual import on, work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static

from argo.providers import CodingProfile, generate, list_models, load_settings, model_limits, save_profile

PRESETS = {"ollama": "http://127.0.0.1:11434", "openai": "https://api.openai.com/v1", "anthropic": "https://api.anthropic.com/v1"}


class ModelDialog(ModalScreen):
    def __init__(self, settings_path):
        super().__init__()
        self.settings_path = settings_path
        self.settings = load_settings(settings_path)
        self.loading_profile = False

    def compose(self):
        profile = self.settings.coding
        with Vertical(id="model-dialog"):
            yield Label("CODING MODEL", classes="dialog-title")
            with VerticalScroll(id="model-fields"):
                yield Static("This model coordinates tools and edits code. Remote endpoints receive selected source and task context.", classes="muted")
                yield Label("Saved profile")
                yield Select([(p.name, p.name) for p in self.settings.profiles] + [("+ New profile", "__new__")], value=profile.name, allow_blank=False, id="coding-profile")
                yield Label("Profile name")
                yield Input(profile.name, id="coding-name")
                yield Label("API protocol")
                yield Select([("Ollama", "ollama"), ("OpenAI-compatible", "openai"), ("Anthropic-compatible", "anthropic")], value=profile.protocol, allow_blank=False, id="coding-protocol")
                yield Label("Base URL — local or remote")
                yield Input(profile.base_url, id="coding-url", placeholder="http://localhost:1234/v1 or https://your-provider/v1")
                yield Label("Hush credential name — optional, never paste an API key")
                yield Input(profile.credential, id="coding-credential", placeholder="e.g. argo-cloud; empty for no authentication")
                yield Label("Model ID — any ID exposed by your endpoint")
                yield Input(profile.model, id="coding-model")
                yield Select([], prompt="Discover models or enter an ID above", id="coding-discovered")
                yield Label("OpenAI JSON output")
                yield Select([("Prompt only — broad compatibility", "prompt"), ("JSON object", "json_object"), ("JSON schema", "json_schema")], value=profile.output_mode, allow_blank=False, id="coding-output")
                yield Label("OpenAI token parameter")
                yield Select([("max_tokens", "max_tokens"), ("max_completion_tokens", "max_completion_tokens")], value=profile.token_parameter, allow_blank=False, id="coding-token-param")
                yield Label("Context tokens — blank uses model API")
                yield Input(str(profile.context_window or ""), id="coding-context", placeholder="Automatic")
                yield Label("Output token cap — blank uses available model context")
                yield Input(str(profile.max_tokens or ""), id="coding-max-tokens", placeholder="Automatic")
                yield Static("Credentials are read through Hush. Save a key in Bitwarden, import it with hush pull --name NAME, then enter only NAME here.", classes="muted")
            yield Static("Choose an endpoint and model, then save.", id="coding-result", markup=False)
            with Horizontal(classes="dialog-actions"):
                yield Button("Models", id="coding-list")
                yield Button("Test", id="coding-test")
                yield Button("Save", id="coding-save", variant="primary")
                yield Button("Cancel", id="coding-cancel")

    def profile(self):
        def value(name):
            return self.query_one("#coding-" + name, Input).value.strip()
        return CodingProfile(name=value("name"), protocol=self.query_one("#coding-protocol", Select).value,
                             base_url=value("url"), model=value("model"), credential=value("credential"),
                             output_mode=self.query_one("#coding-output", Select).value,
                             token_parameter=self.query_one("#coding-token-param", Select).value,
                             context_window=int(value("context")) if value("context") else None,
                             max_tokens=int(value("max-tokens")) if value("max-tokens") else None)

    @on(Select.Changed, "#coding-profile")
    def choose_profile(self, event):
        if event.value == Select.BLANK:
            return
        profile = next((p for p in self.settings.profiles if p.name == event.value), CodingProfile(name="New endpoint", model="model-id"))
        self.loading_profile = True
        with self.prevent(Select.Changed):
            for field, value in [("name", profile.name), ("url", profile.base_url), ("model", profile.model), ("credential", profile.credential), ("context", str(profile.context_window or "")), ("max-tokens", str(profile.max_tokens or ""))]:
                self.query_one("#coding-" + field, Input).value = value
            for field, value in [("protocol", profile.protocol), ("output", profile.output_mode), ("token-param", profile.token_parameter)]:
                self.query_one("#coding-" + field, Select).value = value
        self.loading_profile = False

    @on(Select.Changed, "#coding-protocol")
    def protocol_changed(self, event):
        if self.loading_profile or event.value == Select.BLANK:
            return
        field = self.query_one("#coding-url", Input)
        if field.value in PRESETS.values():
            field.value = PRESETS[event.value]

    @on(Select.Changed, "#coding-discovered")
    def model_selected(self, event):
        if event.value != Select.BLANK:
            self.query_one("#coding-model", Input).value = str(event.value)

    @on(Button.Pressed)
    def clicked(self, event):
        identity = event.button.id
        if identity == "coding-cancel":
            self.dismiss(None)
            return
        try:
            profile = self.profile()
            if identity == "coding-save":
                save_profile(profile, self.settings_path)
                self.dismiss(profile)
            elif identity in {"coding-list", "coding-test"}:
                self.query_one("#coding-result", Static).update("Contacting selected endpoint…")
                for name in ("coding-list", "coding-test", "coding-save"):
                    self.query_one("#" + name, Button).disabled = True
                self.probe(profile, identity == "coding-list")
        except Exception as exc:
            self.query_one("#coding-result", Static).update(str(exc))

    @work(thread=True, exit_on_error=False)
    def probe(self, profile, discover):
        app = self.app
        try:
            limits = model_limits(profile, refresh=True)
            result = list_models(profile) if discover else generate(profile, [{"role": "user", "content": "Return the object with ok equal to true."}], {"type": "object", "properties": {"ok": {"const": True}}, "required": ["ok"], "additionalProperties": False}, tokens=2048)
            app.call_from_thread(self.probe_done, result, discover, None, limits)
        except Exception as exc:
            app.call_from_thread(self.probe_done, None, discover, str(exc))

    def probe_done(self, result, discover, error, limits=None):
        if not self.is_mounted:
            return
        for name in ("coding-list", "coding-test", "coding-save"):
            self.query_one("#" + name, Button).disabled = False
        if error:
            self.query_one("#coding-result", Static).update(error + ". You can still enter a model ID manually.")
        elif discover:
            self.query_one("#coding-discovered", Select).set_options([(name, name) for name in result])
            self.query_one("#coding-result", Static).update(f"{len(result)} models found. Select one above or enter its ID.")
        else:
            self.query_one("#coding-result", Static).update(f"Connected. Context: {limits.context_window:,} tokens. Output: {limits.max_output_tokens or 'not advertised'}. {limits.source}.")
