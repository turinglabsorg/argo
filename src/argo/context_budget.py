import json
import math

from pydantic import BaseModel, Field


class ModelLimits(BaseModel):
    context_window: int = Field(default=16384, ge=1024, le=100_000_000)
    max_output_tokens: int | None = Field(default=None, ge=1, le=100_000_000)
    source: str = "Fallback: endpoint did not advertise limits"

    @property
    def margin(self):
        return max(512, math.ceil(self.context_window * 0.1))

    @property
    def input_budget(self):
        reserve = min(self.max_output_tokens or 4096, max(256, min(4096, self.context_window // 4), self.context_window // 10))
        return self.context_window - self.margin - reserve

    def output_budget(self, messages, schema, cap=None):
        remaining = self.context_window - self.margin - estimate_tokens([messages, schema])
        if remaining < 256:
            raise ValueError("Model context is full. Reduce selected source or start a new task.")
        return min(remaining, self.max_output_tokens or cap or 4096, cap or self.context_window)

    def initial_output(self, messages, schema, cap=None):
        allowance = self.output_budget(messages, schema, cap)
        demand = max(4096, self.context_window // 32, estimate_tokens(messages) * 2)
        return min(allowance, demand)


def estimate_tokens(value):
    return math.ceil(len(json.dumps(value, ensure_ascii=False).encode()) / 3) + 32
