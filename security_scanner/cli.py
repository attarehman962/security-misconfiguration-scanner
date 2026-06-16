"""Command-line interface for running the scanner from a terminal."""

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from security_scanner.core import ScannerError, configure_logging
from security_scanner.reports import format_json, format_table
from security_scanner.scanner import run_scan
from security_scanner.utils import validate_url

SUPPORTED_OUTPUT_FORMATS: tuple[str, str] = ("json", "table")
logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line parser for the security_scanner.

    Returns:
        Configured argparse ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="security-scanner",
        description=(
            "Security Misconfiguration Scanner CLI. "
            "Fetches a target URL, checks common security headers, "
            "checks SSL basics, and returns a structured scan result."
        ),
        epilog=(
            "Examples:\n"
            "  python -m security_scanner --url https://example.com\n"
            "  python -m security_scanner --url https://example.com --format json\n"
            "  python -m security_scanner --url https://example.com --format table\n"
            "  python -m security_scanner --url https://example.com "
            "--output result.json\n"
            "  python -m security_scanner --url https://example.com --verbose"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # argparse calls validate_url before run_scan(), so invalid targets
    # fail early and no network request is made for bad CLI input.
    parser.add_argument(
        "--url",
        required=True,
        type=validate_url,
        help="Target URL to scan. Must start with http:// or https://.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to save the scan result as JSON.",
    )

    parser.add_argument(
        "--format",
        choices=SUPPORTED_OUTPUT_FORMATS,
        default="table",
        help="Terminal output format. Choices: json, table. Default: table.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress messages to stderr.",
    )

    return parser


def save_json_output(output_path: Path, json_output: str) -> None:
    """
    Save JSON output to a file.

    Args:
        output_path: Destination file path.
        json_output: JSON string to write.

    Raises:
        OSError: If the file cannot be written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json_output + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """
    Run the scanner CLI.

    Args:
        argv: Optional argument list for tests. If None, argparse reads from
            sys.argv.

    Returns:
        Process exit code.
    """
    parser = build_parser()
    parsed_arguments = parser.parse_args(argv)
    configure_logging(verbose=parsed_arguments.verbose)

    try:
        if parsed_arguments.verbose:
            print(f"Scanning target: {parsed_arguments.url}", file=sys.stderr)

        # The CLI only coordinates input/output; scanner logic lives in runner.py.
        logger.info("CLI scan requested url=%s", parsed_arguments.url)
        scan_result = run_scan(parsed_arguments.url)
    except (RuntimeError, ScannerError) as error:
        logger.error("CLI scan failed url=%s error=%s", parsed_arguments.url, error)
        print(f"Scanner failed: {error}", file=sys.stderr)
        return 1

    # Always build JSON once because it is used for both --format json and
    # optional --output file writing.
    json_output = format_json(scan_result)

    if parsed_arguments.format == "json":
        print(json_output)
    else:
        print(format_table(scan_result))

    if parsed_arguments.output is not None:
        try:
            # Parent directories are created inside save_json_output().
            save_json_output(parsed_arguments.output, json_output)
        except OSError as error:
            logger.error(
                "CLI could not write output file path=%s error=%s",
                parsed_arguments.output,
                error,
            )
            print(f"Could not write output file: {error}", file=sys.stderr)
            return 1

        logger.info("CLI saved JSON report path=%s", parsed_arguments.output)
        print(
            f"Saved JSON report to: {parsed_arguments.output}",
            file=sys.stderr,
        )

    logger.info("CLI scan completed url=%s", parsed_arguments.url)
    return 0
