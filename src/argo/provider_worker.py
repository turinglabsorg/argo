import json
import os
import sys

from argo.providers import CodingProfile, exchange


def main():
    key = os.environ.pop("ARGO_PROVIDER_KEY", "")
    try:
        raw = sys.stdin.buffer.read(2 * 1024**2 + 1)
        if len(raw) > 2 * 1024**2:
            raise ValueError("Provider request budget exceeded")
        data = json.loads(raw)
        result = exchange(CodingProfile.model_validate(data["profile"]), data["operation"], data.get("messages"), data.get("schema"), data.get("tokens", 4096), key=key)
        text = json.dumps({"result": result})
        print(text.replace(key, "[redacted]") if key else text)
    except (RuntimeError, TimeoutError) as exc:
        message = str(exc)
        print(json.dumps({"error": message.replace(key, "[redacted]") if key else message}))
    except Exception:
        print(json.dumps({"error": "Authenticated provider request failed; check endpoint, model, credential and response format"}))


if __name__ == "__main__":
    main()
