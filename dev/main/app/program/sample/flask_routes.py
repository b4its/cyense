"""Vulnerable Flask route sample (CY003): <int:id> straight into ORM get."""

from __future__ import annotations

from flask import Flask

from .models import Invoice

app = Flask(__name__)


@app.route("/invoice/<int:invoice_id>")
def invoice_detail(invoice_id):
    return Invoice.objects.get(id=invoice_id)
