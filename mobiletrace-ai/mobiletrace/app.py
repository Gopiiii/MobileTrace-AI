"""Entrypoint for the MobileTrace AI PySide6 Windows desktop application."""

from __future__ import annotations

import sys

from mobiletrace.config import load_config
from mobiletrace.db.repository import ForensicRepository


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print(
            "PySide6 is not installed in this environment. Install desktop dependencies with:\n"
            "  pip install -r requirements.txt\n"
            "Or run `python3 -m mobiletrace.cli --help` for the CLI engine.",
            file=sys.stderr,
        )
        return 1

    from mobiletrace.ui.main_window import MobileTraceMainWindow

    config = load_config()
    repo = ForensicRepository(config.db_path)

    app = QApplication(sys.argv)
    app.setApplicationName("MobileTrace AI")
    window = MobileTraceMainWindow(config, repo)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
