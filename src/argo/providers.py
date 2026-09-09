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
from jsonschema import Draft202012Validator, ValidationError
from pydantic import BaseModel, ConfigDict, Field, model_validator

from argo.context_budget import ModelLimits
from argo.evidence import clean, private_dir
from argo.provider_usage import capture_usage
from argo.sandbox import AdapterTimeoutError, command

SETTINGS = Path.home() / ".argo" / "models.json"
DEFAULT_MODEL = "argo-coder:30b-a3b"
OPENROUTER_APP_URL = "https://github.com/turinglabsorg/argo"
LIMIT_CACHE = {}
MAX_PROVIDER_RETRIES = 5


class ProviderTransientError(RuntimeError):
    def __init__(self, code):
        self.code = code if code in {"timeout", "connection"} else "connection"
        super().__init__("Provider request timed out" if self.code == "timeout" else "Provider connection interrupted")


class ProviderRetryExhausted(RuntimeError):
    pass


class ProviderHTTPError(RuntimeError):
    def __init__(self, status, retry_after=None, shared_pool=False):
        self.status = status
        self.retry_after = retry_after
        self.shared_pool = shared_pool
        if status == 429:
            message = "Upstream shared provider pool is rate-limited" if shared_pool else "Provider rate limit reached"
            if retry_after is not None:
                message += f"; retry after {retry_after} seconds"
        else:
            message = {401: "Provider rejected authentication", 403: "Provider denied this request", 402: "Provider credit or spending limit reached", 404: "Endpoint or model not found"}.get(status, "Provider request failed; check the endpoint, model and JSON mode")
        super().__init__(f"HTTP {status}: {message}")


class ProviderResponseError(ValueError):
    MESSAGES = {
        "output_limit": "Provider response was truncated: output token limit reached",
        "filtered": "Provider filtered the response",
        "incomplete": "Provider stream ended before completion",
        "invalid_json": "Provider returned invalid JSON",
        "invalid_schema": "Provider response does not match the requested JSON schema",
        "invalid_format": "Provider returned an unsupported response format",
        "response_limit": "Provider response exceeded the transport size limit",
    }

    def __init__(self, code, validation=None):
        self.code = code if code in self.MESSAGES else "invalid_format"
        self.validation = validation
        super().__init__(self.MESSAGES[self.code])


def response_validation(error):
    details = {"schema_path": list(error.absolute_schema_path), "constraint": error.validator}
    if error.validator in {"type", "required", "enum", "const", "maxLength", "minLength", "maxItems", "minItems", "additionalProperties"}:
        details["expected"] = error.validator_value
    return details


class CodingProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(default="Local Qwen", min_length=1, max_length=80)
    protocol: Literal["ollama", "openai", "anthropic"] = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str = Field(default=DEFAULT_MODEL, min_length=1, max_length=200)
    credential: str = Field(default="", pattern=r"^[a-zA-Z0-9_-]{0,80}$")
    output_mode: Literal["prompt", "json_object", "json_schema"] = "prompt"
    token_parameter: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    max_tokens: int | None = Field(default=None, ge=256, le=100_000_000)
    context_window: int | None = Field(default=None, ge=1024, le=100_000_000)

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
    if not isinstance(content, str):
        raise ProviderResponseError("invalid_format")
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text).strip()
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ProviderResponseError("invalid_json") from exc
    try:
        Draft202012Validator(schema).validate(data)
    except ValidationError as exc:
        raise ProviderResponseError("invalid_schema", response_validation(exc)) from exc
    return data


def request(profile, operation, messages=None, schema=None, tokens=4096, check=lambda: None, session_id=None, on_usage=lambda _: None):
    if not profile.credential:
        try:
            return exchange(profile, operation, messages, schema, tokens, check, session_id=session_id, on_usage=on_usage)
        except httpx.TimeoutException as exc:
            raise ProviderTransientError("timeout") from exc
        except (httpx.NetworkError, httpx.RemoteProtocolError) as exc:
            raise ProviderTransientError("connection") from exc
    binary = shutil.which("hush") or str(Path.home() / ".local/bin/hush")
    if not Path(binary).is_file():
        raise RuntimeError("Hush is required for this credential. Install Hush or choose a profile without authentication.")
    payload = {"profile": profile.model_dump(), "operation": operation, "messages": clean(messages), "schema": schema, "tokens": tokens, "session_id": session_id}
    try:
        code, output, _ = command(
            [binary, "run", "--name", profile.credential, "--env", "ARGO_PROVIDER_KEY", "--redact", "--", sys.executable, "-I", "-m", "argo.provider_worker"],
            360, check, json.dumps(payload).encode(),
        )
    except AdapterTimeoutError as exc:
        raise ProviderTransientError("timeout") from exc
    if code:
        raise RuntimeError("Hush could not run the provider. Check the credential name and vault readiness.")
    result = json.loads(output)
    for usage in result.get("usage", []):
        on_usage(usage)
    if "error" in result:
        if result.get("code") in {"timeout", "connection"}:
            raise ProviderTransientError(result["code"])
        if result.get("code") in ProviderResponseError.MESSAGES:
            raise ProviderResponseError(result["code"], result.get("validation"))
        if result.get("code") == "http":
            raise ProviderHTTPError(result["status"], result.get("retry_after"), result.get("shared_pool", False))
        raise RuntimeError(result["error"])
    return result["result"]


def exchange(profile, operation, messages=None, schema=None, tokens=4096, check=lambda: None, key="", session_id=None, on_usage=lambda _: None):
    headers = {"Accept": "application/json, text/event-stream"}
    endpoint = urlsplit(profile.base_url)
    openrouter = endpoint.scheme == "https" and endpoint.hostname == "openrouter.ai" and endpoint.port in {None, 443}
    if openrouter:
        headers.update({
            "HTTP-Referer": OPENROUTER_APP_URL,
            "X-OpenRouter-Title": "Argo",
            "X-OpenRouter-Categories": "cli-agent",
        })
        if operation == "generate" and session_id is not None:
            if not isinstance(session_id, str) or not re.fullmatch(r"[a-zA-Z0-9._:-]{1,256}", session_id):
                raise ValueError("Invalid provider session identifier")
            headers["x-session-id"] = session_id
    if profile.protocol == "anthropic":
        headers["anthropic-version"] = "2023-06-01"
        if key:
            headers["x-api-key"] = key
    elif key:
        headers["Authorization"] = "Bearer " + key
    started = time.monotonic()
    with httpx.Client(timeout=httpx.Timeout(60, connect=5), trust_env=False, follow_redirects=False) as client:
        if operation == "limits" and profile.protocol == "ollama":
            url = profile.url().removesuffix("/api/chat") + "/api/show"
            with client.stream("POST", url, headers=headers, json={"model": profile.model}) as response:
                data = bounded_json(response, check, started)
            advertised = [positive_int(value) for name, value in data.get("model_info", {}).items() if name.endswith(".context_length")]
            context = min([16384, *(value for value in advertised if value)])
            return ModelLimits(context_window=context, max_output_tokens=min(4096, context // 2), source="Ollama API; active num_ctx capped at 16,384 for local memory").model_dump()
        if operation in {"models", "limits"}:
            with client.stream("GET", profile.url("models"), headers=headers) as response:
                data = bounded_json(response, check, started)
            rows = data.get("models", []) if profile.protocol == "ollama" else data.get("data", [])
            if not isinstance(rows, list):
                raise ProviderResponseError("invalid_format")
            if operation == "limits":
                row = next((row for row in rows if isinstance(row, dict) and row.get("id") == profile.model), {})
                top = row.get("top_provider") or {}
                if not isinstance(top, dict):
                    raise ProviderResponseError("invalid_format")
                contexts = [positive_int(row.get(name)) for name in ("context_length", "context_window", "max_input_tokens")]
                contexts.append(positive_int(top.get("context_length")))
                context = min((value for value in contexts if value), default=None)
                output = positive_int(top.get("max_completion_tokens")) or positive_int(row.get("max_output_tokens")) or positive_int(row.get("max_completion_tokens"))
                return ModelLimits(context_window=context or 16384, max_output_tokens=output, source="Model API" if context else "Fallback: endpoint did not advertise context length").model_dump()
            return sorted({row.get("name") if profile.protocol == "ollama" else row.get("id") for row in rows if isinstance(row, dict) and isinstance(row.get("name") if profile.protocol == "ollama" else row.get("id"), str)})
        messages = clean(messages or [])
        instruction = "Return only a JSON object matching this schema, without prose or markdown:\n" + json.dumps(schema)
        messages = [{"role": "system", "content": instruction}, *messages]
        limit = min(tokens, profile.max_tokens or tokens)
        body = {"model": profile.model, "messages": messages, "stream": True}
        if profile.protocol == "ollama":
            body.update(format=schema, think=False, keep_alive="5m", options={"temperature": 0, "num_ctx": profile.context_window or 16384, "num_predict": limit})
        elif profile.protocol == "openai":
            body[profile.token_parameter] = limit
            if openrouter:
                body["stream_options"] = {"include_usage": True}
            if profile.output_mode == "json_object":
                body["response_format"] = {"type": "json_object"}
            elif profile.output_mode == "json_schema":
                body["response_format"] = {"type": "json_schema", "json_schema": {"name": "argo_result", "schema": schema, "strict": False}}
            if openrouter and profile.output_mode in {"json_object", "json_schema"}:
                body["provider"] = {"require_parameters": True}
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
                raise http_error(response)
            usage = {"response_complete": False}
            try:
                content = decode_generation(response, profile.protocol, check, started, usage)
                result = parse_json(content, schema)
                usage["response_complete"] = True
                return result
            except (KeyError, IndexError, TypeError) as exc:
                raise ProviderResponseError("invalid_format") from exc
            except json.JSONDecodeError as exc:
                raise ProviderResponseError("invalid_json") from exc
            finally:
                on_usage(usage)


def budget(check, started, received):
    check()
    if received > 16 * 1024**2:
        raise ProviderResponseError("response_limit")
    if time.monotonic() - started > 300:
        raise ProviderTransientError("timeout")


def bounded_json(response, check, started):
    if response.status_code >= 300:
        raise http_error(response)
    content = bytearray()
    for part in response.iter_bytes():
        content.extend(part)
        budget(check, started, len(content))
    try:
        data = json.loads(content)
    except ValueError as exc:
        raise ProviderResponseError("invalid_json") from exc
    if not isinstance(data, dict):
        raise ProviderResponseError("invalid_format")
    return data


def http_error(response):
    retry_after, shared_pool = None, False
    value = response.headers.get("retry-after", "")
    if value.isdigit():
        retry_after = min(int(value), 86400)
    if response.status_code == 429:
        content = bytearray()
        for chunk in response.iter_bytes():
            content.extend(chunk)
            if len(content) > 64000:
                break
        try:
            metadata = json.loads(content).get("error", {}).get("metadata", {})
            shared_pool = metadata.get("limit_source") == "upstream_provider_shared_pool"
            if retry_after is None:
                retry_after = positive_int(metadata.get("retry_after_seconds"))
        except (ValueError, AttributeError, TypeError):
            pass
    return ProviderHTTPError(response.status_code, retry_after, shared_pool)


def decode_generation(response, protocol, check, started, usage=None):
    usage = usage if usage is not None else {}
    if protocol != "ollama" and "text/event-stream" not in response.headers.get("content-type", ""):
        data = bounded_json(response, check, started)
        capture_usage(usage, data, protocol)
        if protocol == "anthropic":
            if data.get("stop_reason") == "max_tokens":
                raise ProviderResponseError("output_limit")
            return "".join(item.get("text", "") for item in data["content"] if item["type"] == "text")
        choice = data["choices"][0]
        if choice.get("finish_reason") in {"length", "content_filter"}:
            raise ProviderResponseError("output_limit" if choice.get("finish_reason") == "length" else "filtered")
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
        capture_usage(usage, data, protocol)
        if "error" in data or data.get("type") == "error":
            error = data.get("error")
            if isinstance(error, dict):
                code = error.get("code")
                if isinstance(code, str) and code.isdigit():
                    code = int(code)
                if isinstance(code, int) and not isinstance(code, bool) and 400 <= code <= 599:
                    raise ProviderHTTPError(code)
                if error.get("type") in {"overloaded_error", "api_error"}:
                    raise ProviderHTTPError(529 if error["type"] == "overloaded_error" else 500)
            raise RuntimeError("Provider reported a generation error")
        if protocol == "ollama":
            content += data.get("message", {}).get("content", "")
            done = data.get("done", False)
        elif protocol == "openai":
            for choice in data.get("choices", []):
                content += choice.get("delta", {}).get("content") or ""
                if choice.get("finish_reason") in {"length", "content_filter"}:
                    raise ProviderResponseError("output_limit" if choice.get("finish_reason") == "length" else "filtered")
                done = done or choice.get("finish_reason") == "stop"
        else:
            kind = data.get("type")
            if kind == "content_block_start" and data["content_block"].get("type") == "text":
                content += data["content_block"].get("text", "")
            if kind == "content_block_delta" and data["delta"].get("type") == "text_delta":
                content += data["delta"]["text"]
            if kind == "message_delta" and data.get("delta", {}).get("stop_reason") == "max_tokens":
                raise ProviderResponseError("output_limit")
            done = done or kind == "message_stop"
    check()
    if not done:
        raise ProviderResponseError("incomplete")
    return content


def positive_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 100_000_000 else None


def model_limits(profile, check=lambda: None, refresh=False):
    cache_key = (profile.protocol, profile.base_url, profile.model, profile.credential, profile.context_window)
    cached = LIMIT_CACHE.get(cache_key)
    if cached and not refresh and time.monotonic() - cached[0] < 300:
        return cached[1]
    check()
    try:
        limits = ModelLimits.model_validate(request(profile, "limits", check=check))
    except (httpx.HTTPError, OSError, RuntimeError, ValueError, TimeoutError):
        check()
        limits = ModelLimits(source="Fallback: model limits unavailable from endpoint")
    if profile.context_window:
        limits = limits.model_copy(update={"context_window": profile.context_window, "source": "User context override"})
    LIMIT_CACHE[cache_key] = (time.monotonic(), limits)
    return limits


def retry_wait(seconds, check):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        check()
        time.sleep(min(0.1, max(0, until - time.monotonic())))
    check()


def retry_reason(error):
    if isinstance(error, ProviderTransientError):
        return str(error)
    if isinstance(error, ProviderHTTPError) and error.status in {408, 500, 502, 503, 504, 522, 524, 529}:
        return "Temporary provider failure (HTTP " + str(error.status) + ")"
    if isinstance(error, ProviderResponseError) and error.code == "incomplete":
        return "Provider stream ended before completion"
    return None


def generate(profile, messages, schema, check=lambda: None, tokens=None, on_retry=lambda _: None, session_id=None, on_usage=lambda _: None):
    limits = model_limits(profile, check)
    allowed = limits.output_budget(messages, schema, profile.max_tokens)
    current = min(tokens, allowed) if tokens else limits.initial_output(messages, schema, profile.max_tokens)
    retries = expansions = 0
    while True:
        check()
        try:
            result = request(profile, "generate", messages, schema, current, check, session_id=session_id, on_usage=on_usage)
            break
        except ProviderResponseError as exc:
            if exc.code == "output_limit":
                if current >= allowed or expansions == 3:
                    raise
                current = min(allowed, current * 4) if expansions < 2 else allowed
                expansions += 1
                continue
            reason = retry_reason(exc)
            if reason is None:
                raise
        except (ProviderTransientError, ProviderHTTPError) as exc:
            reason = retry_reason(exc)
            if reason is None:
                raise
        if retries == MAX_PROVIDER_RETRIES:
            on_retry({"phase": "exhausted", "retry": retries, "max_retries": MAX_PROVIDER_RETRIES, "reason": reason})
            raise ProviderRetryExhausted(reason + "; stopped after 5 automatic retries")
        retries += 1
        delay = 2 ** (retries - 1)
        details = {"retry": retries, "max_retries": MAX_PROVIDER_RETRIES, "reason": reason, "delay_seconds": delay}
        on_retry({"phase": "waiting", **details})
        retry_wait(delay, check)
        on_retry({"phase": "retrying", **details})
    if retries:
        on_retry({"phase": "recovered", "retry": retries, "max_retries": MAX_PROVIDER_RETRIES})
    try:
        Draft202012Validator(schema).validate(result)
    except ValidationError as exc:
        raise ProviderResponseError("invalid_schema", response_validation(exc)) from exc
    return result


def list_models(profile, check=lambda: None):
    return request(profile, "models", check=check)
