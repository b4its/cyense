"""Sample vulnerable Django-style module for mode=program scans (PRD §4.2).

Expected rule hits: CY001, CY002, CY005, CY006 (4 of 6 — acceptance #4).
CY003/CY004 live in flask_routes.py / fastapi_routes.py respectively.
"""

from __future__ import annotations

from django.shortcuts import get_object_or_404

from .models import Invoice, ReportFile


def invoice_detail(request):
    # CY001: unscoped .get() by request id
    invoice = Invoice.objects.get(id=request.GET["id"])
    return invoice


def invoice_first(request):
    # CY002: unscoped filter().first()
    invoice = Invoice.objects.filter(id=request.GET["id"]).first()
    return invoice


def invoice_404(request):
    # CY005: get_object_or_404 without user scoping
    invoice = get_object_or_404(Invoice, pk=request.GET["pk"])
    return invoice


def download(request):
    # CY006: request-controlled filesystem path (critical)
    name = request.GET["name"]
    with open(f"/uploads/{name}") as handle:
        return handle.read()


def safe_detail(request):
    # scoped -> no finding
    return Invoice.objects.get(id=request.GET["id"], user_id=request.user.id)
