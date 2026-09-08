import json

from argo.sandbox import command

MONGODB_IMAGE = "mongo@sha256:43fddee7e532a920f3dfdee9e8f4834398c155c26bcb92d790cc1cd3c630fc40"
MONGODB_URI = "mongodb://127.0.0.1:27017/argo_test"


def database_mode(value):
    if value not in {"off", "mongodb"}:
        raise ValueError("Test database must be off or mongodb")
    return value


def start_mongodb(worker, name, check):
    code, _, _ = command(["docker", "image", "inspect", MONGODB_IMAGE], 10, check)
    if code:
        raise RuntimeError("Install the pinned test database with: docker pull " + MONGODB_IMAGE)
    args = [
        "docker", "run", "--pull", "never", "-d", "--name", name,
        "--network", "container:" + worker, "--read-only", "--user", "999:999",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
        "--memory", "1g", "--memory-swap", "1g", "--cpus", "1",
        "--tmpfs", "/data/db:rw,nosuid,nodev,size=768m,uid=999,gid=999,mode=700",
        "--tmpfs", "/data/configdb:rw,nosuid,nodev,size=16m,uid=999,gid=999,mode=700",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m,mode=1777",
        "--label", "dev.argo.test-database=true", "--entrypoint", "mongod", MONGODB_IMAGE,
        "--bind_ip", "127.0.0.1", "--port", "27017", "--nounixsocket",
        "--wiredTigerCacheSizeGB", "0.25", "--quiet",
    ]
    code, _, _ = command(args, 30, check)
    if code:
        raise RuntimeError("Cannot start the isolated MongoDB test database")
    code, output, _ = command(["docker", "inspect", name], 10, check)
    if code:
        raise RuntimeError("Cannot inspect the test database")
    detail = json.loads(output)[0]
    host = detail["HostConfig"]
    if (
        host["NetworkMode"] != "container:" + worker
        or detail["Mounts"] or host.get("PortBindings") or host["Privileged"]
        or not host["ReadonlyRootfs"] or detail["Config"]["User"] != "999:999"
    ):
        raise RuntimeError("Test database isolation validation failed")
    probe = "import socket,time\nfor attempt in range(150):\n try:\n  socket.create_connection(('127.0.0.1',27017),timeout=0.2).close();break\n except OSError:\n  time.sleep(0.1)\nelse:\n raise SystemExit(1)"
    code, _, _ = command(["docker", "exec", worker, "python", "-I", "-c", probe], 20, check)
    if code:
        raise RuntimeError("MongoDB test database did not become ready on worker loopback")
    return {"kind": "mongodb", "image": MONGODB_IMAGE, "container": name, "container_id": detail["Id"], "uri": MONGODB_URI,
            "network": "worker loopback only", "persistent": False}
