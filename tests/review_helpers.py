import json


def unpack_review(payload):
    document = json.loads(payload)
    if document.get('encoding') != 'shared-json-v1':
        return document

    def expand(value):
        if isinstance(value, dict):
            if set(value) == {'$argo_ref'}:
                return expand(document['shared_values'][value['$argo_ref']])
            return {key: expand(child) for key, child in value.items()}
        if isinstance(value, list):
            return [expand(child) for child in value]
        return value

    return expand(document['context'])
