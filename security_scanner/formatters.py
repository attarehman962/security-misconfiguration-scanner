import json
from typing import Any

from security_scanner.models import ScanResult
from security_scanner.serializers import serialize_scan_result


MAX_COLUMN_WIDTH = 70


def format_json(scan_result: ScanResult) -> str:
    """
    Format a scan result as pretty JSON.

    Args:
        scan_result: Complete scan result.

    Returns:
        JSON string.
    """
    serialized_result = serialize_scan_result(scan_result)
    return json.dumps(serialized_result, indent=2, sort_keys=True)


def format_table(scan_result: ScanResult) -> str:
    """
    Format a scan result as a readable terminal table.

    Args:
        scan_result: Complete scan result.

    Returns:
        Terminal-friendly table string.
    """
    serialized_result = serialize_scan_result(scan_result)
    findings = serialized_result["findings"]

    lines = [
        f"Scan result for: {serialized_result['url']}",
        f"Timestamp: {serialized_result['timestamp']}",
        f"Total score: {serialized_result['total_score']}",
        "",
    ]

    if not findings:
        lines.append("No findings returned.")
        return "\n".join(lines)

    headers = ("Header", "Passed", "Severity", "Message")
    rows = [
        (
            _truncate(str(finding["header"]), 30),
            _truncate(str(finding["passed"]), 10),
            _truncate(str(finding["severity"]), 10),
            _truncate(str(finding["message"]), MAX_COLUMN_WIDTH),
        )
        for finding in findings
    ]

    column_widths = _calculate_column_widths(headers, rows)

    separator = _build_separator(column_widths)
    lines.append(separator)
    lines.append(_build_row(headers, column_widths))
    lines.append(separator)

    for row in rows:
        lines.append(_build_row(row, column_widths))

    lines.append(separator)
    return "\n".join(lines)


def _truncate(value: str, max_width: int) -> str:
    """
    Truncate long text for readable terminal output.

    Args:
        value: Original string.
        max_width: Maximum visible width.

    Returns:
        Possibly truncated string.
    """
    if len(value) <= max_width:
        return value

    return f"{value[: max_width - 3]}..."


def _calculate_column_widths(
    headers: tuple[str, str, str, str],
    rows: list[tuple[str, str, str, str]],
) -> tuple[int, int, int, int]:
    """
    Calculate table column widths from headers and rows.

    Args:
        headers: Table header labels.
        rows: Table row values.

    Returns:
        Width for each column.
    """
    all_rows = [headers, *rows]

    return (
        max(len(row[0]) for row in all_rows),
        max(len(row[1]) for row in all_rows),
        max(len(row[2]) for row in all_rows),
        max(len(row[3]) for row in all_rows),
    )


def _build_separator(column_widths: tuple[int, int, int, int]) -> str:
    """
    Build a table separator line.

    Args:
        column_widths: Width of each column.

    Returns:
        Separator string.
    """
    return (
        "+"
        + "+".join("-" * (width + 2) for width in column_widths)
        + "+"
    )


def _build_row(
    values: tuple[str, str, str, str],
    column_widths: tuple[int, int, int, int],
) -> str:
    """
    Build a table row.

    Args:
        values: Row values.
        column_widths: Width of each column.

    Returns:
        Formatted table row.
    """
    return (
        f"| {values[0]:<{column_widths[0]}} "
        f"| {values[1]:<{column_widths[1]}} "
        f"| {values[2]:<{column_widths[2]}} "
        f"| {values[3]:<{column_widths[3]}} |"
    )
