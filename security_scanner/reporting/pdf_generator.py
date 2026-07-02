import io
from typing import Protocol

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from security_scanner.schemas.reports import FindingRow, ReportData

_STYLES = getSampleStyleSheet()
_BODY_STYLE = ParagraphStyle(
    "Body", parent=_STYLES["BodyText"], fontSize=9, leading=12
)
_SEVERITY_COLORS: dict[str, colors.Color] = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#b91c1c"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#65a30d"),
    "Info": colors.HexColor("#6b7280"),
}


class _FooterCanvas(Protocol):
    def saveState(self) -> None: ...

    def setFont(
        self, psfontname: str, size: float, leading: float | None = None
    ) -> None: ...

    def drawCentredString(self, x: float, y: float, text: str) -> None: ...

    def restoreState(self) -> None: ...


class _FooterDocument(Protocol):
    page: int


def _invariant_canvas(*args, **kwargs) -> Canvas:
    """Canvas factory that strips wall-clock timestamps and random IDs.

    ReportLab's default Canvas embeds the current time in
    /CreationDate and /ModDate and generates a random /ID, which
    would make PDF output non-deterministic across calls. Passing
    invariant=True disables both, which is required for
    generate_pdf_report's byte-identical-output guarantee to hold.
    """
    kwargs["invariant"] = 1
    return Canvas(*args, **kwargs)


def generate_pdf_report(data: ReportData) -> bytes:
    """Build a complete PDF security report and return it as raw bytes.

    This function is pure: given identical ReportData, it produces
    byte-identical PDF output on every call (no wall-clock reads,
    no randomness), which keeps it deterministic and testable.
    """
    buffer = io.BytesIO()
    doc = _build_doc_template(buffer)

    story = []
    story.extend(_build_header(data))
    story.extend(_build_summary(data))
    story.extend(_build_findings_table(data.findings))
    story.extend(_build_remediation_section(data.findings))

    doc.build(story, canvasmaker=_invariant_canvas)
    return buffer.getvalue()


def _build_doc_template(buffer: io.BytesIO) -> BaseDocTemplate:
    """Create a document template with margins sized for a footer."""
    frame = Frame(
        2 * cm, 2 * cm, A4[0] - 4 * cm, A4[1] - 4 * cm, id="main_frame"
    )
    doc = BaseDocTemplate(buffer, pagesize=A4)
    doc.addPageTemplates(
        [PageTemplate(id="report", frames=[frame], onPage=_draw_footer)]
    )
    return doc


def _build_header(data: ReportData) -> list:
    """Render the report title block: project name, target, scan date."""
    title_style = ParagraphStyle("Title", parent=_STYLES["Title"], fontSize=18)
    meta_style = ParagraphStyle("Meta", parent=_STYLES["Normal"], fontSize=10)

    return [
        Paragraph(data.project_name, title_style),
        Paragraph(f"Target: {data.scan_url}", meta_style),
        Paragraph(
            f"Scan date: {data.scan_date.strftime('%Y-%m-%d %H:%M UTC')}",
            meta_style,
        ),
        Spacer(1, 0.6 * cm),
    ]


def _build_summary(data: ReportData) -> list:
    """Render the executive summary table."""
    summary = data.summary
    rows = [
        ["Risk Score", f"{summary.risk_score} / 100"],
        ["Risk Level", summary.risk_level],
        ["Total Checks", str(summary.total_checks)],
        ["Passed", str(summary.passed_count)],
        ["Failed", str(summary.failed_count)],
    ]
    table = Table(rows, colWidths=[6 * cm, 6 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return [
        Paragraph("Executive Summary", _STYLES["Heading2"]),
        table,
        Spacer(1, 0.6 * cm),
    ]


def _build_findings_table(findings: list[FindingRow]) -> list:
    """Render the findings table; handles the zero-findings edge case."""
    if not findings:
        return [
            Paragraph("Findings", _STYLES["Heading2"]),
            Paragraph("No checks were recorded for this scan.", _BODY_STYLE),
            Spacer(1, 0.6 * cm),
        ]

    header: list[str | Paragraph] = ["Check Name", "Status", "Severity", "Description"]
    rows: list[list[str | Paragraph]] = [header]
    for finding in findings:
        status = "Pass" if finding.passed else "Fail"
        rows.append(
            [
                Paragraph(finding.check_name, _BODY_STYLE),
                status,
                finding.severity.value,
                Paragraph(finding.description or "—", _BODY_STYLE),
            ]
        )

    table = Table(rows, colWidths=[4 * cm, 1.8 * cm, 2.2 * cm, 7.5 * cm], repeatRows=1)
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ]
    for row_index, finding in enumerate(findings, start=1):
        if not finding.passed:
            severity_color = _SEVERITY_COLORS.get(finding.severity.value, colors.black)
            style_commands.append(
                ("TEXTCOLOR", (2, row_index), (2, row_index), severity_color)
            )
    table.setStyle(TableStyle(style_commands))

    return [Paragraph("Findings", _STYLES["Heading2"]), table, Spacer(1, 0.6 * cm)]


def _build_remediation_section(findings: list[FindingRow]) -> list:
    """Render remediation guidance for each failed check only."""
    failed = [f for f in findings if not f.passed]
    if not failed:
        return []

    elements: list[Paragraph | Spacer] = [Paragraph("Remediation", _STYLES["Heading2"])]
    for finding in failed:
        elements.append(Paragraph(finding.check_name, _STYLES["Heading4"]))
        remediation_text = finding.remediation or "No remediation guidance available."
        elements.append(Paragraph(remediation_text, _BODY_STYLE))
        elements.append(Spacer(1, 0.3 * cm))
    return elements


def _draw_footer(canvas: _FooterCanvas, doc: _FooterDocument) -> None:
    """Draw page number footer on every page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(A4[0] / 2, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()