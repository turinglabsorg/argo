import argparse
import asyncio
import re
from pathlib import Path

from argo.services import DEFAULT_STATE
from argo.tui import ArgoApp


def main():
    parser = argparse.ArgumentParser(description="Capture the Argo TUI with Textual Pilot")
    parser.add_argument("output", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--width", type=int, default=140)
    parser.add_argument("--height", type=int, default=44)
    args = parser.parse_args()

    async def capture():
        app = ArgoApp(DEFAULT_STATE)
        async with app.run_test(size=(args.width, args.height)) as pilot:
            for _ in range(100):
                await pilot.pause(0.1)
                if app.ollama_status != "checking":
                    break
            if args.run_id:
                app.resume(args.run_id)
                await pilot.pause()
            screenshot = app.export_screenshot()
            screenshot = re.sub(r"@font-face\s*\{[^}]+\}", "", screenshot)
            screenshot = screenshot.replace("font-family: Fira Code, monospace;", "font-family: Menlo;")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(screenshot)

    asyncio.run(capture())


if __name__ == "__main__":
    main()
