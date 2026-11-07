"""
Standalone Executable & Module Entrypoint for Sentinel-X (`python -m sentinel_x` or `sentinel-x.exe`).
- When invoked with CLI arguments: executes the requested SOC or Release Protection command.
- When double-clicked on Windows (invoked with no arguments): starts the local-first
  Sentinel-X Security Dashboard on http://127.0.0.1:8080 so the console stays open interactively.
"""

from __future__ import annotations

import sys
from typing import List, Optional

from sentinel_x.cli import main as soc_cli_main
from sentinel_x.security.release_protection.cli import main as release_cli_main


def run_entrypoint(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    # If user double-clicks sentinel-x.exe on Windows (no arguments), start the dashboard server
    if not args:
        print("======================================================================")
        print("  Sentinel-X Cybersecurity & SOC Platform (Standalone Mode)")
        print("  No CLI arguments provided -> Starting Local Security Dashboard...")
        print("  URL: http://127.0.0.1:8080   (Press Ctrl+C to stop)")
        print("  Tip: Run 'sentinel-x.exe --help' in Command Prompt for CLI commands.")
        print("======================================================================")
        return soc_cli_main(["serve", "--host", "127.0.0.1", "--port", "8080"])

    # Route 'release-protection ...' directly to the Anti-REA CLI
    if args[0] == "release-protection":
        return release_cli_main(args[1:])

    return soc_cli_main(args)


if __name__ == "__main__":
    sys.exit(run_entrypoint())
