"""CSV export for scan findings (enhanced-reporting-viewer.md §3.3).

Exports findings to CSV format for data analysis and integration with other tools.
"""
from __future__ import annotations

import csv
import io
from typing import Any


def export_csv(findings: list[dict[str, Any]], include_remediation: bool = True) -> str:
    """
    Export findings to CSV format.

    Args:
        findings: List of finding dictionaries
        include_remediation: Whether to include remediation column

    Returns:
        CSV string with UTF-8 BOM for Excel compatibility
    """
    output = io.StringIO()

    # Write UTF-8 BOM for Excel compatibility
    output.write('\ufeff')

    # Define columns
    fieldnames = [
        'finding_id',
        'rule',
        'severity',
        'cvss_score',
        'cvss_vector',
        'cwe',
        'title',
        'description',
        'location',
        'snippet',
        'confidence',
    ]

    if include_remediation:
        fieldnames.append('remediation')

    fieldnames.append('verified_at')

    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()

    for finding in findings:
        # Prepare row data
        row = {
            'finding_id': finding.get('finding_id', ''),
            'rule': finding.get('rule', ''),
            'severity': finding.get('severity', ''),
            'cvss_score': finding.get('cvss_score', ''),
            'cvss_vector': finding.get('cvss_vector', ''),
            'cwe': finding.get('cwe', ''),
            'title': finding.get('title', ''),
            'description': finding.get('description', ''),
            'location': finding.get('location', ''),
            'snippet': (
                finding.get('evidence', {}).get('snippet')
                or finding.get('evidence', {}).get('code')
                or finding.get('body_snippet')
                or ''
            ),
            'confidence': finding.get('confidence', ''),
            'verified_at': finding.get('verified_at', ''),
        }

        if include_remediation:
            row['remediation'] = finding.get('remediation', '')

        writer.writerow(row)

    return output.getvalue()
