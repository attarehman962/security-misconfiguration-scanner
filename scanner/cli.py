import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from scanner.formatters import format_json, format_table
from scanner.runner import run_full_scan
from scanner.validators import validate_url


SUPPORTED_OUTPUT_FORMATS: tuple[str, str] = ("json", "table")


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line parser for the scanner.

    Returns:
        Configured argparse ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            "Security Misconfiguration Scanner CLI. "
            "Fetches a target URL, checks common security headers, "
            "checks SSL basics, and returns a structured scan result."
        ),
        epilog=(
            "Examples:\n"
            "  python -m scanner --url https://example.com\n"
            "  python -m scanner --url https://example.com --format json\n"
            "  python -m scanner --url https://example.com --format table\n"
            "  python -m scanner --url https://example.com --output result.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

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


def main(arguments: Sequence[str] | None = None) -> int:
    """
    Run the scanner CLI.

    Args:
        arguments: Optional argument list for tests. If None, argparse
            reads from sys.argv.

    Returns:
        Process exit code.
    """
    parser = build_parser()
    parsed_arguments = parser.parse_args(arguments)

    try:
        scan_result = run_full_scan(parsed_arguments.url)
    except RuntimeError as error:
        print(f"Scanner failed: {error}", file=sys.stderr)
        return 2

    json_output = format_json(scan_result)

    if parsed_arguments.format == "json":
        print(json_output)
    else:
        print(format_table(scan_result))

    if parsed_arguments.output is not None:
        try:
            save_json_output(parsed_arguments.output, json_output)
        except OSError as error:
            print(f"Could not write output file: {error}", file=sys.stderr)
            return 2

        print(
            f"Saved JSON report to: {parsed_arguments.output}",
            file=sys.stderr,
        )

    return 0