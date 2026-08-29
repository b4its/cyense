"""Vulnerable FastAPI route sample (CY004): path param into ORM get."""

from __future__ import annotations

from fastapi import FastAPI

from .models import Invoice

app = FastAPI()


@app.get("/orders/{order_id}")
async def read_order(order_id: int):
    return Invoice.objects.get(id=order_id)
