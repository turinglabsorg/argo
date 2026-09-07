import os
import socket
import struct


def bson(document):
    data = b""
    for key, value in document.items():
        name = key.encode() + b"\0"
        if isinstance(value, str):
            encoded = value.encode() + b"\0"
            data += b"\x02" + name + struct.pack("<i", len(encoded)) + encoded
        elif isinstance(value, int):
            data += b"\x10" + name + struct.pack("<i", value)
        elif isinstance(value, dict):
            data += b"\x03" + name + bson(value)
        else:
            data += b"\x04" + name + bson({str(i): item for i, item in enumerate(value)})
    return struct.pack("<i", len(data) + 5) + data + b"\0"


def receive(connection, length):
    result = b""
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        assert chunk, "Incomplete MongoDB response"
        result += chunk
    return result


def query(document):
    body = b"\0" * 5 + bson({**document, "$db": "argo_test"})
    packet = struct.pack("<iiii", len(body) + 16, 1, 0, 2013) + body
    with socket.create_connection(("127.0.0.1", 27017), timeout=2) as connection:
        connection.sendall(packet)
        header = receive(connection, 16)
        length, _, _, opcode = struct.unpack("<iiii", header)
        assert opcode == 2013 and 16 < length < 65536
        response = receive(connection, length - 16)
        assert b"\x01ok\0" + struct.pack("<d", 1.0) in response, response
        return response


assert os.environ["ARGO_TEST_MONGODB_URI"] == "mongodb://127.0.0.1:27017/argo_test"
assert b"owned-argo-document" not in query({"find": "controls", "filter": {}})
assert b"writeErrors" not in query({"insert": "controls", "documents": [{"value": "owned-argo-document"}]})
assert b"owned-argo-document" in query({"find": "controls", "filter": {"value": "owned-argo-document"}})
assert b"owned-argo-document" not in query({"find": "controls", "filter": {"value": "missing"}})
for address in ["1.1.1.1", "169.254.169.254", "192.168.65.254"]:
    try:
        socket.create_connection((address, 80), timeout=0.2)
    except OSError:
        continue
    raise AssertionError("External network reachable: " + address)
print("Real MongoDB insert/find and negative controls passed; external network denied")
