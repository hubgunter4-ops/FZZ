"""PyInstaller entry point for the FZZ CLI/GUI executable."""
from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1].lower() == "gui":
        from fzztool.gui import launch
        launch()
        return 0
    from fzztool.cli import main as cli_main
    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
