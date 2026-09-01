"""PDF report generation for compliance/audit (enhanced-reporting-viewer.md §3.2).

Uses reportlab library to generate professional PDF reports with CVSS/CWE info.
"""
from __future__ import annotations

import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
    scan_id: str,
    title: str = "Cyense Security Assessment Report",
) -> bytes:
    """
    Generate PDF report for scan findings.

    Args:
        findings: List of finding dictionaries
        summary: Summary dictionary with counts by severity
        scan_id: Scan identifier
        title: Report title

    Returns:
        PDF as bytes
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    # Create document elements
    elements = []

    # Title
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#0a1628'),
        spaceAfter=30,
        alignment=TA_CENTER,
    )
    elements.append(Paragraph(title, title_style))

    # Meta info table
    meta_data = [
        ["Scan ID:", scan_id],
        ["Generated At:", "Current timestamp"],
        [
            "Severity Breakdown:",
            (
                f"Critical: {summary.get('critical', 0)}, "
                f"High: {summary.get('high', 0)}, "
                f"Medium: {summary.get('medium', 0)}, "
                f"Low: {summary.get('low', 0)}"
            ),
        ],
    ]

    meta_table = Table(meta_data, colWidths=[1.5 * inch, 4.5 * inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e0e6ed')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, '#f5f5f5']),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 0.3 * inch))

    # Severity breakdown
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Heading2'], fontSize=14)
    elements.append(Paragraph("Findings Overview", subtitle_style))
    elements.append(Spacer(1, 0.1 * inch))

    total = max(summary.get('total', 1), 1)

    def _pct(key: str) -> str:
        return f"{summary.get(key, 0) / total * 100:.1f}%"

    severity_data = [
        ['Severity', 'Count', 'Percentage'],
        ['Critical', str(summary.get('critical', 0)), _pct('critical')],
        ['High', str(summary.get('high', 0)), _pct('high')],
        ['Medium', str(summary.get('medium', 0)), _pct('medium')],
        ['Low', str(summary.get('low', 0)), _pct('low')],
    ]

    severity_table = Table(severity_data, colWidths=[3*inch, 1.2*inch, 1.3*inch])
    severity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0a1628')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, '#f0f0f0']),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(severity_table)
    elements.append(PageBreak())

    # Detailed findings
    elements.append(Paragraph("Detailed Findings", subtitle_style))
    elements.append(Spacer(1, 0.1 * inch))

    for idx, finding in enumerate(findings, 1):
        # Finding header
        finding_title = f"{idx}. {finding.get('rule', '')}: {finding.get('title', '')}"
        title_style = ParagraphStyle(
            'FindingTitle', parent=styles['Heading3'],
            fontSize=11, textColor=colors.HexColor('#1a2332'),
        )
        elements.append(Paragraph(finding_title, title_style))
        elements.append(Spacer(1, 0.1 * inch))

        # Finding details
        details = [
            ['Severity:', severity_badge(finding.get('severity', ''))],
            ['CVSS Score:', str(finding.get('cvss_score', 'N/A'))],
            ['CWE:', str(finding.get('cwe', 'N/A'))],
            ['Location:', str(finding.get('location', 'N/A'))],
            ['Confidence:', f"{(finding.get('confidence') or 0) * 100:.0f}%"],
        ]

        details_table = Table(details, colWidths=[1.5 * inch, 5 * inch])
        details_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(details_table)
        elements.append(Spacer(1, 0.2 * inch))

        # Description if available
        if finding.get('description'):
            desc_style = ParagraphStyle(
                'Description', parent=styles['Normal'], fontSize=9, leading=10
            )
            elements.append(Paragraph('Description:', desc_style))
            elements.append(Paragraph(str(finding.get('description', '')), desc_style))
            elements.append(Spacer(1, 0.2 * inch))

        # Remediation if available
        if finding.get('remediation'):
            rem_style = ParagraphStyle(
                'Remediation', parent=styles['Normal'], fontSize=9, leading=10,
                textColor=colors.HexColor('#0066cc'),
            )
            elements.append(Paragraph('Remediation:', rem_style))
            elements.append(Paragraph(str(finding.get('remediation', '')), rem_style))
            elements.append(Spacer(1, 0.3 * inch))

        elements.append(PageBreak())

    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer.read()


def severity_badge(severity: str) -> str:
    """Return formatted severity badge."""
    badges = {
        'critical': '[CRITICAL]',
        'high': '[HIGH]',
        'medium': '[MEDIUM]',
        'low': '[LOW]',
        'info': '[INFO]',
    }
    return badges.get(severity.lower(), '[UNKNOWN]')
