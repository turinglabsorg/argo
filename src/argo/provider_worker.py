import json
import os
import sys

import httpx

from argo.providers import (
    CodingProfile,
    ProviderHTTPError,
    ProviderResponseError,
    ProviderTransientError,
    exchange,
)


def main():
    key = os.environ.pop("ARGO_PROVIDER_KEY", "")
    usage = []
    try:
        raw = sys.stdin.buffer.read(16 * 1024**2 + 1)
        if len(raw) > 16 * 1024**2:
            raise ValueError("Provider request budget exceeded")
        data = json.loads(raw)
        result = exchange(CodingProfile.model_validate(data["profile"]), data["operation"], data.get("messages"), data.get("schema"), data.get("tokens", 4096), key=key, session_id=data.get("session_id"), on_usage=usage.append)
        reply = {"result": result}
    except ProviderResponseError as exc:
        reply = {"error": str(exc), "code": exc.code}
    except ProviderHTTPError as exc:
        reply = {"error": str(exc), "code": "http", "status": exc.status, "retry_after": exc.retry_after, "shared_pool": exc.shared_pool}
    except ProviderTransientError as exc:
        reply = {"error": str(exc), "code": exc.code}
    except httpx.TimeoutException:
        reply = {"error": "Provider request timed out", "code": "timeout"}
    except (httpx.NetworkError, httpx.RemoteProtocolError):
        reply = {"error": "Could not connect to the provider endpoint", "code": "connection"}
    except httpx.HTTPError:
        reply = {"error": "Provider transport configuration failed"}
    except (RuntimeError, TimeoutError) as exc:
        reply = {"error": str(exc)}
    except Exception:
        reply = {"error": "Provider request failed before a valid response could be read"}
    text = json.dumps({**reply, "usage": usage})
    print(text.replace(key, "[redacted]") if key else text)


if __name__ == "__main__":
    main()
