import math
import re


def capture_usage(record, data, protocol):
    if not isinstance(data, dict):
        return
    source = data.get("message", {}) if protocol == "anthropic" and data.get("type") == "message_start" else data
    if not isinstance(source, dict):
        return
    for name in ("id", "model", "provider"):
        value = source.get(name)
        if isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9 ._:/-]{1,200}", value):
            record["generation_id" if name == "id" else name] = value
    usage = source.get("usage")
    if not isinstance(usage, dict):
        return
    details = usage.get("prompt_tokens_details")
    details = details if isinstance(details, dict) else {}
    values = {
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "cached_tokens": details.get("cached_tokens"),
        "cache_write_tokens": details.get("cache_write_tokens"),
    }
    if protocol == "anthropic":
        values.update(
            uncached_input_tokens=usage.get("input_tokens"),
            completion_tokens=usage.get("output_tokens"),
            cached_tokens=usage.get("cache_read_input_tokens"),
            cache_write_tokens=usage.get("cache_creation_input_tokens"),
        )
    for name, value in values.items():
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000_000:
            record[name] = value
    if protocol == "anthropic" and "uncached_input_tokens" in record:
        record["prompt_tokens"] = sum(record.get(name, 0) for name in ("uncached_input_tokens", "cached_tokens", "cache_write_tokens"))
    cost = usage.get("cost")
    if isinstance(cost, (float, int)) and not isinstance(cost, bool) and 0 <= cost <= 1_000_000 and math.isfinite(cost):
        record["cost_usd"] = cost


def summarize_usage(records):
    measured = [row for row in records if isinstance(row.get("prompt_tokens"), int) and isinstance(row.get("cached_tokens"), int) and 0 <= row["cached_tokens"] <= row["prompt_tokens"]]
    prompt = sum(row["prompt_tokens"] for row in measured)
    cached = sum(row["cached_tokens"] for row in measured)
    costs = [row["cost_usd"] for row in records if "cost_usd" in row]
    return {
        "responses": len(records),
        "cache_measured_responses": len(measured),
        "cache_hit_responses": sum(row["cached_tokens"] > 0 for row in measured),
        "measured_prompt_tokens": prompt if measured else None,
        "cached_tokens": cached if measured else None,
        "cache_hit_ratio": cached / prompt if prompt else None,
        "reported_cost_usd": sum(costs) if costs else None,
        "cost_measured_responses": len(costs),
    }
