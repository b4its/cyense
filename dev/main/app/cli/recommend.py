"""Algoritma agregasi saran perbaikan (cli-experience.md §3.5).

Dipakai oleh renderer.py (terminal) DAN md_report.py (markdown) —
satu sumber kebenaran untuk prioritas.

Aturan:
1. Kelompokkan findings[] berdasarkan `rule`.
2. Skor: bobot_severity_maks × confidence_maks × log2(1 + jumlah_temuan)
3. Urutkan menurun; seri diputus oleh `rule` (leksikografis).
4. Klasifikasi: quick_win / structural / priority.
5. Teks tindakan diambil dari field `remediation` temuan berskor tertinggi.
6. Daftar terdampak dari `location`, maks 5 + ringkasan.
"""

from __future__ import annotations

from typing import Any

from app.cli.models import (
    SEVERITY_WEIGHT,
    Recommendation,
    classify_recommendation,
    get_finding_dict,
    score_group,
)


def build_recommendations(findings: list[Any]) -> list[Recommendation]:
    """
    Terima list Finding (Pydantic model atau dict), kembalikan list
    Recommendation terurut dari prioritas tertinggi ke terendah.
    """
    if not findings:
        return []

    # -- 1. Kelompokkan per rule
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        fd = get_finding_dict(f)
        rule = fd.get("rule", "UNKNOWN")
        groups.setdefault(rule, []).append(fd)

    recs: list[Recommendation] = []

    for rule, group in groups.items():
        # -- 2. Hitung skor kelompok
        severities = [fd.get("severity", "info") for fd in group]
        confidences = [float(fd.get("confidence", 0.0)) for fd in group]

        # Severity tertinggi berdasarkan bobot
        sev_max = max(severities, key=lambda s: SEVERITY_WEIGHT.get(s, 0))
        conf_max = max(confidences) if confidences else 0.0
        n = len(group)
        sc = score_group(sev_max, conf_max, n)

        # -- 5. Teks tindakan: dari temuan dengan confidence tertinggi
        best = max(group, key=lambda fd: float(fd.get("confidence", 0.0)))
        action = best.get("remediation") or f"Tinjau penggunaan rule {rule} secara manual."

        # -- 6. Daftar lokasi (maks 5 + ringkasan)
        locations = [
            fd.get("location") or fd.get("evidence", {}).get("file", "")
            for fd in group
            if fd.get("location") or fd.get("evidence", {})
        ]
        locations = [loc for loc in locations if loc]
        if len(locations) > 5:
            extra = len(locations) - 5
            locations = locations[:5] + [f"… dan {extra} lokasi lainnya"]

        # -- 4. Klasifikasi
        all_locs = [
            fd.get("location") or ""
            for fd in group
        ]
        category = classify_recommendation(sev_max, all_locs)

        recs.append(Recommendation(
            rule=rule,
            severity=sev_max,
            max_confidence=conf_max,
            occurrences=n,
            score=sc,
            category=category,
            action=action,
            affected=locations,
        ))

    # -- 3. Urutkan: skor menurun, seri diputus oleh rule leksikografis
    recs.sort(key=lambda r: (-r.score, r.rule))

    return recs
