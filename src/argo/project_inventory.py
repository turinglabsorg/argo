import csv
import hashlib
import json
import re
import tomllib
from pathlib import PurePosixPath
from urllib.parse import urlsplit

VERSION = re.compile(r"\d[0-9A-Za-z.+_-]{0,100}\Z")
NAME = re.compile(r"(?:@[a-z0-9_.-]+/)?[A-Za-z0-9_.-]{1,180}\Z")
PUBLIC_SCOPES = {"@types", "@google-cloud", "@mongodb-js", "@babel", "@esbuild", "@typescript-eslint", "@vitest", "@rollup", "@opentelemetry", "@aws-sdk", "@smithy", "@jridgewell", "@nodelib", "@eslint", "@eslint-community", "@humanfs", "@humanwhocodes", "@isaacs", "@pkgjs", "@sinonjs", "@tsconfig", "@ungap", "@grpc", "@protobufjs", "@resvg", "@swc", "@next", "@nestjs"}
REGISTRIES = {"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org"}
FRAMEWORKS = {"express", "next", "react", "vue", "nuxt", "fastify", "koa", "hapi", "mongoose", "mongodb", "pg", "mysql2", "redis", "django", "flask", "fastapi", "starlette", "jinja2", "sqlalchemy", "aiohttp"}
PRODUCTS = {"node": ("Node.js", "nodejs", "node.js"), "python": ("Python", "python", "python"), "mongo": ("MongoDB", "mongodb", "mongodb"), "postgres": ("PostgreSQL", "postgresql", "postgresql"), "redis": ("Redis", "redis", "redis"), "nginx": ("nginx", "f5", "nginx"), "httpd": ("Apache HTTP Server", "apache", "http_server")}


def public_registry(value):
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return parsed.scheme == "https" and parsed.hostname in REGISTRIES and not parsed.username and not parsed.password


def inventory(manifests, source_files=None):
    files = manifests.get("files", {})
    gaps = list(manifests.get("coverage_gaps", []))
    packages, technologies, declared, groups, yarn_selectors = {}, [], {}, {}, {}

    def add(ecosystem, name, version, path, public=True):
        if not isinstance(name, str) or not NAME.fullmatch(name) or not isinstance(version, str) or not VERSION.fullmatch(version):
            gaps.append(path + ": unresolved package version or unsupported name")
            return
        if name.startswith("@") and name.split("/")[0] not in PUBLIC_SCOPES:
            public = False
        key = (ecosystem, name.lower() if ecosystem == "PyPI" else name, version, path)
        packages[key] = {"ecosystem": ecosystem, "name": name, "version": version, "path": path, "public": public, "version_source": "lockfile" if PurePosixPath(path).name != "requirements.txt" else "exact_requirement"}

    for path, source in sorted(files.items()):
        name = PurePosixPath(path).name
        try:
            if name == "package.json":
                data = json.loads(source)
                root = str(PurePosixPath(path).parent)
                declared[root] = {**data.get("dependencies", {}), **data.get("devDependencies", {}), **data.get("optionalDependencies", {})}
                groups[root] = {section: set(data.get(section, {})) for section in ("dependencies", "devDependencies", "optionalDependencies")}
                technologies.append({"name": "Node.js", "path": path, "version": data.get("engines", {}).get("node"), "version_source": "declared_range"})
            elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
                data = json.loads(source)
                if data.get("lockfileVersion") not in (1, 2, 3):
                    raise ValueError("Unsupported npm lock version")
                if data.get("lockfileVersion") == 1:
                    pending = list(data.get("dependencies", {}).items())
                    while pending:
                        package, record = pending.pop()
                        add("npm", package, record.get("version"), path, public_registry(record.get("resolved")))
                        pending.extend(record.get("dependencies", {}).items())
                else:
                    for key, record in data.get("packages", {}).items():
                        if "node_modules/" in key and not record.get("link"):
                            add("npm", record.get("name") or key.rsplit("node_modules/", 1)[1], record.get("version"), path, public_registry(record.get("resolved")))
            elif name == "yarn.lock":
                if "# yarn lockfile v1" not in source[:1000]:
                    raise ValueError("Only Yarn v1 is supported")
                blocks = re.split(r"(?m)^(?=[^\s#])", source)
                selectors = yarn_selectors.setdefault(str(PurePosixPath(path).parent), set())
                for block in blocks:
                    lines = block.splitlines()
                    if not lines or not lines[0].endswith(":"):
                        continue
                    version = re.search(r'^  version "([^"\n]+)"$', block, re.M)
                    resolved = re.search(r'^  resolved "([^"\n]+)"$', block, re.M)
                    if not version:
                        raise ValueError("Yarn entry has no exact version")
                    for selector in next(csv.reader([lines[0][:-1]], skipinitialspace=True)):
                        selectors.add(selector)
                        package, _, spec = selector.rpartition("@")
                        if not package or "@npm:" in package or spec.startswith(("file:", "link:", "workspace:", "git", "http")):
                            gaps.append(path + ": a Yarn alias or non-registry dependency was skipped")
                            continue
                        add("npm", package, version[1], path, bool(resolved and public_registry(resolved[1])))
            elif name in {"uv.lock", "poetry.lock"}:
                data = tomllib.loads(source)
                for record in data.get("package", []):
                    origin = record.get("source", {})
                    registry = origin.get("registry") or origin.get("url")
                    public = public_registry(registry) if registry else name == "poetry.lock" and not origin
                    if name == "uv.lock" and not registry:
                        continue
                    add("PyPI", record["name"], record["version"], path, public)
            elif name == "requirements.txt":
                private_index = any(line.strip().startswith(("--index-url", "--extra-index-url", "-i ")) for line in source.splitlines())
                for line in source.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9_.+-]+)(?:\s*[;#].*)?", line)
                    if match:
                        add("PyPI", match[1], match[2], path, not private_index)
                    else:
                        gaps.append(path + ": unpinned requirement, include or index option was not resolved")
            elif name == "pyproject.toml":
                tomllib.loads(source)
                technologies.append({"name": "Python", "path": path, "version": None, "version_source": "manifest"})
            elif name in {"pnpm-lock.yaml", "bun.lock"}:
                gaps.append(path + ": lockfile format is not supported; exact dependency coverage is missing")
            elif name == "Dockerfile" or name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
                pattern = r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)" if name == "Dockerfile" else r'(?m)^\s*image:\s*["\x27]?([^\s"\x27#]+)'
                for image in re.findall(pattern, source):
                    tag, _, _digest = image.partition("@")
                    product, _, version = tag.partition(":")
                    product = product.removeprefix("docker.io/library/")
                    if product in PRODUCTS:
                        title, vendor, cpe_product = PRODUCTS[product]
                        exact = re.match(r"^(\d+\.\d+\.\d+)(?:-|$)", version)
                        technologies.append({"name": title, "path": path, "version": exact[1] if exact else version or None, "version_source": "image_tag", "cpe": f"cpe:2.3:a:{vendor}:{cpe_product}:{exact[1]}:*:*:*:*:*:*:*" if exact else None})
                        if not exact:
                            gaps.append(path + ": " + title + " image tag does not determine an exact runtime version")
        except (ValueError, TypeError, KeyError, AttributeError, csv.Error):
            gaps.append(path + ": manifest could not be fully parsed")

    for root, dependencies in declared.items():
        lock_paths = {str(PurePosixPath(p[3]).parent) for p in packages if p[0] == "npm"}
        if root not in lock_paths:
            gaps.append((root + "/" if root != "." else "") + "package.json: no supported resolved lockfile; ranges were not treated as installed versions")
        for package, requirement in dependencies.items():
            if root in yarn_selectors and f"{package}@{requirement}" not in yarn_selectors[root]:
                gaps.append((root + "/" if root != "." else "") + "package.json: declared constraints are missing from yarn.lock; resolutions may be out of sync")
            if package in FRAMEWORKS:
                technologies.append({"name": package, "version": str(requirement)[:100], "path": (root + "/" if root != "." else "") + "package.json", "version_source": "declared_range"})
    result = list(packages.values())
    for package in result:
        scope = groups.get(str(PurePosixPath(package["path"]).parent), {})
        package["declared_groups"] = [group for group, names in scope.items() if package["name"] in names] or ["transitive_or_unknown"]
        package["usage_paths"] = [path for path, source in (source_files or {}).items() if path not in files and ("'" + package["name"] + "'" in source or '"' + package["name"] + '"' in source or re.search(r"\b(?:import|from) " + re.escape(package["name"].replace("-", "_")) + r"\b", source))][:8]
        if not package["public"]:
            gaps.append(package["path"] + ": private, custom-registry or unknown-scope dependency excluded from online queries")
    if len(result) > 1500:
        gaps.append("Package inventory truncated at 1,500 resolved entries")
    hashes = {path: hashlib.sha256(source.encode()).hexdigest() for path, source in files.items()}
    return {"technologies": technologies[:100], "packages": result[:1500], "manifest_sha256": hashes, "fingerprint": hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(), "coverage_gaps": list(dict.fromkeys(gaps)), "note": "Lockfile versions describe resolutions, not proof of what is deployed. Source references are search hints, not reachability evidence."}
