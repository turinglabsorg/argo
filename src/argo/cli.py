import argparse
import json
import os
import re
import sys
from pathlib import Path

from argo.advisories import load_mode
from argo.agent import import_sources, restore, run_agent
from argo.agent_models import MODELS
from argo.contracts import Actions, Engagement, Scope
from argo.controller import run
from argo.evidence import read_state, redact, verify
from argo.mcp import MCPClient, default_profile, load_profile
from argo.providers import load_settings
from argo.scope import ScopeError, authorize, digest, load, normalize, save
from argo.services import CYBER_MODELS, DEFAULT_STATE, demo, doctor, run_path
from argo.tui import ArgoApp


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(
        prog="argo", description="Review code, apply fixes and verify security findings"
    )
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("tui").add_argument("file", nargs="?", type=Path)
    commands.add_parser("doctor")
    commands.add_parser("runs")
    sub = commands.add_parser("agent", help="Run the agent in an offline Docker workspace")
    sub.add_argument("task")
    inputs = sub.add_mutually_exclusive_group()
    inputs.add_argument("--import", dest="source", type=Path, help="Copy sanitized project sources; originals stay outside the worker")
    inputs.add_argument("--continue", dest="previous", help="Continue the verified workspace of a saved run")
    inputs.add_argument("--project", type=Path, help="Mount this directory read/write (default: current directory)")
    inputs.add_argument("--isolated", action="store_true", help="Use a disposable workspace without a project mount")
    sub.add_argument("--no-mcp", action="store_true")
    sub.add_argument("--test-database", choices=["off", "mongodb"], default="off", help="Start a temporary database on isolated worker loopback")
    sub.add_argument("--intelligence", choices=["offline", "connected"], help="Override saved CVE intelligence mode for this task")
    sub.add_argument("--mcp-profile", type=Path)
    sub.add_argument("--max-steps", type=int, default=24)
    sub.add_argument("--planner", choices=MODELS, help="Explicit local coordinator override; otherwise use the TUI-selected coding profile")
    commands.add_parser("mcp-tools").add_argument("--profile", type=Path)
    init = commands.add_parser("init")
    init.add_argument("file", type=Path)
    init.add_argument("--id", required=True)
    init.add_argument("--repo", action="append", default=[])
    init.add_argument("--origin", action="append", default=[])
    init.add_argument(
        "--active-web",
        action="store_true",
        help="Enable bounded CORS and Git metadata checks after authorization",
    )
    init.add_argument("--purpose", default="Authorized security audit")
    approval = commands.add_parser("authorize", help="Record operator authorization of the displayed scope")
    approval.add_argument("file", type=Path)
    approval.add_argument("--operator", required=True)
    approval.add_argument("--reference", required=True)
    approval.add_argument("--hours", type=int, default=4)
    commands.add_parser("plan").add_argument("file", type=Path)
    for name in ("run", "retest", "demo"):
        sub = commands.add_parser(name)
        if name != "demo":
            sub.add_argument("file", type=Path)
            sub.add_argument("--cache", type=Path)
        if name == "retest":
            sub.add_argument("--previous", required=True)
        sub.add_argument("--no-model", action="store_true")
        sub.add_argument("--model", action="append", choices=CYBER_MODELS)
        sub.add_argument(
            "--scanners",
            action="store_true",
            help="Run digest-pinned Semgrep and Gitleaks with Docker network disabled",
        )
    for name in ("status", "stop", "report", "verify"):
        commands.add_parser(name).add_argument("run_id")
    args = parser.parse_args()
    try:
        if args.command == "tui" or (args.command is None and sys.stdin.isatty()):
            ArgoApp(args.state_dir, getattr(args, "file", None)).run()
            return 0
        if args.command is None:
            parser.print_help()
            return 0
        if args.command == "doctor":
            output = doctor()
        elif args.command == "agent":
            options = {
                "use_mcp": not args.no_mcp,
                "profile": load_profile(args.mcp_profile) if args.mcp_profile else None,
                "max_steps": args.max_steps,
                "test_database": args.test_database,
                "intelligence_mode": args.intelligence or load_mode(args.state_dir.parent / "intelligence-settings.json"),
                "on_progress": lambda event: print(json.dumps(event), file=sys.stderr, flush=True),
            }
            if args.planner:
                options["planner"] = args.planner
            else:
                options["coding"] = load_settings().coding
            seed = import_sources(args.source) if args.source else (restore(run_path(args.state_dir, args.previous)) if args.previous else {})
            project = None if args.source or args.previous or args.isolated else (args.project or Path.cwd())
            output = run_agent(args.task, args.state_dir, seed=seed, project=project, **options)
        elif args.command == "mcp-tools":
            client = MCPClient(load_profile(args.profile) if args.profile else default_profile())
            output = {"server": client.profile.name, "tools": client.discover()}
        elif args.command == "runs":
            output = {
                "runs": [
                    read_state(path)
                    for path in sorted(args.state_dir.glob("*"))
                    if path.is_dir() and not path.is_symlink() and re.fullmatch(r"[a-f0-9]{32}", path.name)
                ]
            }
        elif args.command == "init":
            if args.file.exists():
                raise ValueError("Engagement file already exists")
            config = Engagement(
                id=args.id,
                purpose=args.purpose,
                scope=Scope(repositories=args.repo, web_origins=args.origin),
                actions=Actions(
                    local_audit=bool(args.repo), web_observe=bool(args.origin), web_validate=args.active_web
                ),
            )
            save(args.file, normalize(config))
            output = {
                "file": str(args.file),
                "status": "draft",
                "next": "Review with argo plan, then record authorization",
            }
        elif args.command in {"authorize", "plan"}:
            config = load(args.file)
            if args.command == "authorize":
                config = authorize(config, args.operator, args.reference, args.hours)
                save(args.file, config)
            output = {"scope_sha256": digest(config), "engagement": config.model_dump(), "target_requests": 0}
        elif args.command in {"run", "retest", "demo"}:
            models = [] if args.no_model else (args.model or CYBER_MODELS)
            if args.command == "demo":
                output = demo(args.state_dir, models, args.scanners)
            else:
                previous = run_path(args.state_dir, args.previous) if args.command == "retest" else None
                output = run(load(args.file), args.state_dir, args.cache, models, args.scanners, previous)
        else:
            path = run_path(args.state_dir, args.run_id)
            if args.command == "status":
                output = read_state(path)
            elif args.command == "verify":
                output = verify(path)
            elif args.command == "stop":
                descriptor = os.open(path / "cancel", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(descriptor)
                output = {"run_id": args.run_id, "status": "cancellation_requested"}
            else:
                output = {"report": str(path / "report.md"), "json": str(path / "report.json")}
        print(json.dumps(output, indent=2))
        return 1 if output.get("status") in {"failed", "cancelled", "incomplete"} else 0
    except Exception as exc:
        message = (
            str(exc) if isinstance(exc, (FileNotFoundError, RuntimeError, ScopeError)) else type(exc).__name__
        )
        print(
            json.dumps(
                {
                    "error": redact(message),
                    "hint": "Check the engagement, service readiness, and argo plan output",
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
