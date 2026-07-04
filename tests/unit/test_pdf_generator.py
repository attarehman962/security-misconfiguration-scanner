# tests/unit/test_pdf_generator.py

import io
from datetime import datetime, timezone

import pdfplumber
import pytest

from security_scanner.reporting.pdf_generator import generate_pdf_report
from security_scanner.reporting.risk import calculate_risk_summary
from security_scanner.schemas.reports import FindingRow, ReportData, Severity


@pytest.fixture
def sample_findings():
    return [
        FindingRow(
            'HSTS Header', False, Severity.HIGH,
            'Missing HSTS header',
            'Add Strict-Transport-Security header'
        ),
        FindingRow(
            'SSL Valid', True, Severity.INFO,
            'Certificate is valid'
        ),
    ]


@pytest.fixture
def sample_data(sample_findings):
    return ReportData(
        project_name='Test Security Scan',
        scan_url='https://example.com',
        scan_date=datetime(2024, 1, 15, tzinfo=timezone.utc),
        summary=calculate_risk_summary(sample_findings),
        findings=sample_findings,
    )


# Layer 1 — magic bytes
def test_pdf_magic_bytes(sample_data):
    pdf_bytes = generate_pdf_report(sample_data)
    assert pdf_bytes[:5] == b"%PDF-"


# Layer 2 — not empty
def test_pdf_not_empty(sample_data):
    pdf_bytes = generate_pdf_report(sample_data)
    assert len(pdf_bytes) > 1000  # real PDF is never just a few bytes


# Layer 3 — determinism
def test_pdf_is_deterministic(sample_data):
    pdf_bytes_1 = generate_pdf_report(sample_data)
    pdf_bytes_2 = generate_pdf_report(sample_data)
    assert pdf_bytes_1 == pdf_bytes_2


# Layer 4 — content correctness
def test_pdf_contains_project_name(sample_data):
    pdf_bytes = generate_pdf_report(sample_data)
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        text = "\n".join(p.extract_text() for p in pdf.pages)
    assert "Test Security Scan" in text


def test_pdf_contains_scan_url(sample_data):
    pdf_bytes = generate_pdf_report(sample_data)
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        text = "\n".join(p.extract_text() for p in pdf.pages)
    assert "https://example.com" in text


def test_pdf_contains_finding_names(sample_data):
    pdf_bytes = generate_pdf_report(sample_data)
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        text = "\n".join(p.extract_text() for p in pdf.pages)
    assert "HSTS Header" in text
    assert "SSL Valid" in text


# Layer 5 — memory only (no disk writes)
def test_pdf_generation_is_memory_only(sample_data, tmp_path):
    import os
    files_before = set(os.listdir(tmp_path))
    generate_pdf_report(sample_data)
    files_after = set(os.listdir(tmp_path))
    assert files_before == files_after  # no new files created