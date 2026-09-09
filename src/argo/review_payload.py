import json
from collections import Counter


def serialize(value, sort_keys=True):
    return json.dumps(value, ensure_ascii=False, sort_keys=sort_keys, separators=(",", ":"))


def review_payload(context):
    original = serialize(context)
    if len(original) < 65536:
        return original, "json"
    counts = Counter()
    collision = False

    def collect(value):
        nonlocal collision
        if not isinstance(value, (dict, list, str)):
            return
        text = serialize(value)
        if len(text) >= 256:
            counts[text] += 1
        if isinstance(value, dict):
            collision |= "$argo_ref" in value
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(context)
    if collision:
        return original, "json"
    identities, shared = {}, {}
    documents = []
    for snapshot in (context, context.get("before", {})):
        documents.extend(value for _, value in sorted(snapshot.get("manifests", {}).items()))
        documents.extend(value for _, value in sorted(snapshot.get("files", {}).items(), key=lambda pair: (not pair[0].startswith("tests/"), pair[0].startswith("tests/argo-security/"), pair[0])))
    for value in documents:
        if len(serialize(value)) >= 256:
            counts[serialize(value)] = max(2, counts[serialize(value)])

    def encode(value, reference=True):
        text = serialize(value) if isinstance(value, (dict, list, str)) else ""
        if reference and counts[text] > 1:
            if text not in identities:
                identity = f"v{len(identities) + 1}"
                identities[text] = identity
                shared[identity] = encode(value, reference=False)
            return {"$argo_ref": identities[text]}
        if isinstance(value, dict):
            return {key: encode(child) for key, child in value.items()}
        if isinstance(value, list):
            return [encode(child) for child in value]
        return value

    for value in documents:
        encode(value)
    encoded = encode(context)
    packed = serialize({"encoding": "shared-json-v1", "shared_values": shared, "context": encoded}, sort_keys=False)
    return (packed, "shared-json-v1") if len(packed) < len(original) else (original, "json")
