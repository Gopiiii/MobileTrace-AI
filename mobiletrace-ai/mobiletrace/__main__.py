"""Allow launching MobileTrace AI via `python -m mobiletrace`."""

from mobiletrace.app import main

if __name__ == "__main__":
    raise SystemExit(main())
