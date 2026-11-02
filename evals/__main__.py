"""Module entry point of the evals command line interface."""

from evals.cli import main

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        raise SystemExit(f"error: {exc}") from None
