import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, model_validator

from argo.evidence import clean, private_dir
from argo.sandbox import command

SETTINGS = Path.home() / ".argo" / "models.json"
DEFAULT_MODEL = "argo-coder:30b-a3b"


class CodingProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(default="Local Qwen", min_length=1, max_length=80)
    protocol: Literal["ollama", "openai", "anthropic"] = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str = Field(default=DEFAULT_MODEL, min_length=1, max_length=200)
    credential: str = Field(default="", pattern=r"^[a-zA-Z0-9_-]{0,80}$")
    output_mode: Literal["prompt", "json_object", "json_schema"] = "prompt"
    token_parameter: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    max_tokens: int = Field(default=8192, ge=256, le=65536)

    @model_validator(mode="after")
    def validate_endpoint(self):
        parsed = urlsplit(self.base_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Use an HTTP(S) base URL without credentials, query or fragment")
        if any(ord(c) < 32 for c in self.base_url + self.model + self.name):
            raise ValueError("Control characters are not allowed in model settings")
        self.base_url = self.base_url.strip().rstrip("/")
        return self

    def url(self, operation="generate"):
        parsed = urlsplit(self.base_url)
        path = parsed.path.rstrip("/")
        for suffix in ("/chat/completions", "/messages", "/models", "/api/chat", "/api/tags"):
            if path.endswith(suffix):
                path = path[:-len(suffix)]
                break
        if self.protocol == "ollama":
            if path.endswith("/api"):
                path = path[:-4]
            path += "/api/tags" if operation == "models" else "/api/chat"
        else:
            if not path:
                path = "/v1"
            path += "/models" if operation == "models" else ("/messages" if self.protocol == "anthropic" else "/chat/completions")
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class ModelSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active: str = "Local Qwen"
    profiles: list[CodingProfile] = Field(default_factory=lambda: [CodingProfile()], min_length=1, max_length=30)

    @model_validator(mode="after")
    def unique_profiles(self):
        names = [profile.name for profile in self.profiles]
        if len(set(names)) != len(names) or self.active not in names:
            raise ValueError("Profiles need unique names and an existing active selection")
        return self

    @property
    def coding(self):
        return next(profile for profile in self.profiles if profile.name == self.active)


def load_settings(path=SETTINGS):
    if not path.exists():
        return ModelSettings()
    if path.is_symlink() or path.stat().st_size > 64000:
        raise ValueError("Invalid model settings file")
    return ModelSettings.model_validate_json(path.read_text())


def save_profile(profile, path=SETTINGS):
    settings = load_settings(path)
    profiles = [item for item in settings.profiles if item.name != profile.name] + [profile]
    settings = ModelSettings(active=profile.name, profiles=profiles)
    private_dir(path.parent)
    descriptor, name = tempfile.mkstemp(prefix=".models-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(settings.model_dump_json(indent=2) + "\n")
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
    return settings


def parse_json(content, schema):
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text).strip()
    data = json.loads(text)
    Draft202012Validator(schema).validate(data)
    return data


def request(profile, operation, messages=None, schema=None, tokens=4096, check=lambda: None):
    if not profile.credential:
        return exchange(profile, operation, messages, schema, tokens, check)
    binary = shutil.which("hush") or str(Path.home() / ".local/bin/hush")
    if not Path(binary).is_file():
        raise RuntimeError("Hush is required for this credential. Install Hush or choose a profile without authentication.")
    payload = {"profile": profile.model_dump(), "operation": operation, "messages": clean(messages), "schema": schema, "tokens": tokens}
    code, output, _ = command(
        [binary, "run", "--name", profile.credential, "--env", "ARGO_PROVIDER_KEY", "--redact", "--", sys.executable, "-I", "-m", "argo.provider_worker"],
        360, check, json.dumps(payload).encode(),
    )
    if code:
        raise RuntimeError("Hush could not run the provider. Check the credential name and vault readiness.")
    result = json.loads(output)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["result"]


def exchange(profile, operation, messages=None, schema=None, tokens=4096, check=lambda: None, key=""):
    headers = {"Accept": "application/json, text/event-stream"}
    if profile.protocol == "anthropic":
        headers["anthropic-version"] = "2023-06-01"
        if key:
            headers["x-api-key"] = key
    elif key:
        headers["Authorization"] = "Bearer " + key
    started = time.monotonic()
    with httpx.Client(timeout=httpx.Timeout(60, connect=5), trust_env=False, follow_redirects=False) as client:
        if operation == "models":
            with client.stream("GET", profile.url("models"), headers=headers) as response:
                data = bounded_json(response, check, started)
            rows = data.get("models", []) if profile.protocol == "ollama" else data.get("data", [])
            return sorted({row.get("name") if profile.protocol == "ollama" else row.get("id") for row in rows if isinstance(row, dict) and isinstance(row.get("name") if profile.protocol == "ollama" else row.get("id"), str)})
        messages = clean(messages or [])
        instruction = "Return only a JSON object matching this schema, without prose or markdown:\n" + json.dumps(schema)
        messages = [{"role": "system", "content": instruction}, *messages]
        limit = min(tokens, profile.max_tokens)
        body = {"model": profile.model, "messages": messages, "stream": True}
        if profile.protocol == "ollama":
            body.update(format=schema, think=False, keep_alive="5m", options={"temperature": 0, "num_ctx": 16384, "num_predict": limit})
        elif profile.protocol == "openai":
            body[profile.token_parameter] = limit
            if profile.output_mode == "json_object":
                body["response_format"] = {"type": "json_object"}
            elif profile.output_mode == "json_schema":
                body["response_format"] = {"type": "json_schema", "json_schema": {"name": "argo_result", "schema": schema, "strict": False}}
        else:
            body["max_tokens"] = limit
            body["system"] = "\n\n".join(item["content"] for item in messages if item["role"] == "system")
            turns = []
            for item in messages:
                if item["role"] == "system":
                    continue
                if turns and turns[-1]["role"] == item["role"]:
                    turns[-1]["content"] += "\n\n" + item["content"]
                else:
                    turns.append(dict(item))
            body["messages"] = turns
        with client.stream("POST", profile.url(), headers=headers, json=body) as response:
            if response.status_code >= 300:
                raise RuntimeError(f"{profile.protocol} endpoint returned HTTP {response.status_code}; check URL, model, credential and JSON mode")
            content = decode_generation(response, profile.protocol, check, started)
    return parse_json(content, schema)


def budget(check, started, received):
    check()
    if received > 2 * 1024**2 or time.monotonic() - started > 300:
        raise TimeoutError("Provider response budget exceeded")


def bounded_json(response, check, started):
    if response.status_code >= 300:
        raise RuntimeError(f"Provider returned HTTP {response.status_code}; check endpoint and credentials")
    content = bytearray()
    for part in response.iter_bytes():
        content.extend(part)
        budget(check, started, len(content))
    return json.loads(content)


def decode_generation(response, protocol, check, started):
    if protocol != "ollama" and "text/event-stream" not in response.headers.get("content-type", ""):
        data = bounded_json(response, check, started)
        if protocol == "anthropic":
            if data.get("stop_reason") == "max_tokens":
                raise ValueError("Provider exhausted its output token budget")
            return "".join(item.get("text", "") for item in data["content"] if item["type"] == "text")
        choice = data["choices"][0]
        if choice.get("finish_reason") in {"length", "content_filter"}:
            raise ValueError("Provider response was truncated or filtered")
        return choice["message"]["content"]
    content, received, done, event = "", 0, False, []
    for line in response.iter_lines():
        received += len(line.encode())
        budget(check, started, received)
        if protocol == "ollama":
            if not line:
                continue
            data = json.loads(line)
        else:
            if line.startswith("data:"):
                event.append(line[5:].lstrip())
                continue
            if line or not event:
                continue
            value, event = "\n".join(event), []
            if value == "[DONE]":
                done = True
                break
            data = json.loads(value)
        if "error" in data or data.get("type") == "error":
            raise RuntimeError("Provider reported a generation error")
        if protocol == "ollama":
            content += data.get("message", {}).get("content", "")
            done = data.get("done", False)
        elif protocol == "openai":
            for choice in data.get("choices", []):
                content += choice.get("delta", {}).get("content") or ""
                if choice.get("finish_reason") in {"length", "content_filter"}:
                    raise ValueError("Provider response was truncated or filtered")
                done = done or choice.get("finish_reason") == "stop"
        else:
            kind = data.get("type")
            if kind == "content_block_start" and data["content_block"].get("type") == "text":
                content += data["content_block"].get("text", "")
            if kind == "content_block_delta" and data["delta"].get("type") == "text_delta":
                content += data["delta"]["text"]
            if kind == "message_delta" and data.get("delta", {}).get("stop_reason") == "max_tokens":
                raise ValueError("Provider exhausted its output token budget")
            done = done or kind == "message_stop"
    check()
    if not done:
        raise ValueError("Provider stream ended before completion")
    return content


def generate(profile, messages, schema, check=lambda: None, tokens=4096):
    result = request(profile, "generate", messages, schema, tokens, check)
    Draft202012Validator(schema).validate(result)
    return result


def list_models(profile, check=lambda: None):
    return request(profile, "models", check=check)
