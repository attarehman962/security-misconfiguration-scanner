"""Runnable demo for Day 01 scanner models."""

from misconfig_scanner.models import Scanner


def main() -> None:
    """Run a demo scan and print the JSON report."""
    scanner = Scanner(target="http://example.com")
    report = scanner.run()
    print(report.to_json())


if __name__ == "__main__":
    main()
