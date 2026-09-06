import json
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, model_validator

from argo.evidence import clean
from argo.workspace import remote_call


class MCPTool(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    arguments: dict


class MCPProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,32}$")
    endpoint: str
    tools: list[MCPTool] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_profile(self):
        parsed = urlsplit(self.endpoint)
        if parsed.scheme != "https" or parsed.port not in {None, 443} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("MCP requires a public HTTPS endpoint without embedded secrets")
        if len({tool.name for tool in self.tools}) != len(self.tools):
            raise ValueError("Duplicate MCP tool")
        for tool in self.tools:
            schema = tool.arguments
            validate_schema(schema)
            if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
                raise ValueError("Operator MCP policy must explicitly restrict arguments")
        return self


def validate_schema(schema):
    if len(json.dumps(schema)) > 16000 or any(key in json.dumps(schema) for key in ['"$ref"', '"$dynamicRef"', '"pattern"', '"patternProperties"']):
        raise ValueError("Schema references and untrusted regular expressions are not supported")
    Draft202012Validator.check_schema(schema)


def default_profile():
    return MCPProfile(
        name="deepwiki", endpoint="https://mcp.deepwiki.com/mcp",
        tools=[MCPTool(name="read_wiki_structure", arguments={
            "type": "object", "properties": {"repoName": {"type": "string", "enum": ["python/cpython", "pallets/flask", "psf/requests", "pytest-dev/pytest"]}},
            "required": ["repoName"], "additionalProperties": False,
        })],
    )


def load_profile(path: Path):
    if path.stat().st_size > 32768:
        raise ValueError("MCP profile too large")
    return MCPProfile.model_validate_json(path.read_text())


class MCPClient:
    def __init__(self, profile, check=lambda: None):
        self.profile = profile
        self.check = check
        self.schemas = {}

    def discover(self):
        data = remote_call(self.profile.endpoint, check=self.check)
        available = {item["name"]: item for item in data["tools"]}
        for rule in self.profile.tools:
            if rule.name not in available:
                raise ValueError("Configured MCP tool is unavailable: " + rule.name)
            schema = available[rule.name]["inputSchema"]
            validate_schema(schema)
            self.schemas[rule.name] = schema
        return [{"tool": "mcp." + rule.name, "arguments": rule.arguments} for rule in self.profile.tools]

    def call(self, name, arguments):
        rule = next((item for item in self.profile.tools if item.name == name), None)
        if not rule or name not in self.schemas:
            raise ValueError("MCP tool is not explicitly allowed and discovered")
        Draft202012Validator(rule.arguments).validate(arguments)
        Draft202012Validator(self.schemas[name]).validate(arguments)
        result = remote_call(self.profile.endpoint, name, arguments, self.check)
        if result.get("isError"):
            raise ValueError("MCP tool returned an error")
        text = json.dumps(clean(result))
        return {"server": self.profile.name, "tool": name, "untrusted_result": text[:16000], "truncated": len(text) > 16000}
