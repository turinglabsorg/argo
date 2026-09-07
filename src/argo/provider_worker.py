import json
import os
import sys

import httpx

from argo.providers import CodingProfile, ProviderHTTPError, ProviderResponseError, exchange


def main():
    key = os.environ.pop("ARGO_PROVIDER_KEY", "")
    try:
        raw = sys.stdin.buffer.read(16 * 1024**2 + 1)
        if len(raw) > 16 * 1024**2:
            raise ValueError("Provider request budget exceeded")
        data = json.loads(raw)
        result = exchange(CodingProfile.model_validate(data["profile"]), data["operation"], data.get("messages"), data.get("schema"), data.get("tokens", 4096), key=key)
        text = json.dumps({"result": result})
        print(text.replace(key, "[redacted]") if key else text)
    except ProviderResponseError as exc:
        print(json.dumps({"error": str(exc), "code": exc.code}))
    except ProviderHTTPError as exc:
        print(json.dumps({"error": str(exc), "code": "http", "status": exc.status, "retry_after": exc.retry_after, "shared_pool": exc.shared_pool}))
    except httpx.TimeoutException:
        print(json.dumps({"error": "Provider request timed out", "code": "timeout"}))
    except httpx.HTTPError:
        print(json.dumps({"error": "Could not connect to the provider endpoint", "code": "connection"}))
    except (RuntimeError, TimeoutError) as exc:
        message = str(exc)
        print(json.dumps({"error": message.replace(key, "[redacted]") if key else message}))
    except Exception:
        print(json.dumps({"error": "Provider request failed before a valid response could be read"}))


if __name__ == "__main__":
    main()
