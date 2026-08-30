"""Vulnerable lab app — Flask (PRD v2.0 §7.3 eval set).

Endpoints intentionally vulnerable/secure to exercise the scanner:

 #  endpoint         ground truth
 1  /invoice/<id>    IDOR critical (PII of other users, control-id 404)
 2  /orders/<id>     IDOR high (object data, no PII, control-id 404)
 3  /profile/<id>    secure (403 for other ids)
 4  /docs/<id>       generic-200 trap (200 for ANY id incl. nonsense)
 5  /api/v2/user/<uid> IDOR high (uuid, direct access works)
 6  /invoice/<id> flaky: /flaky/<id> ambiguous (inconsistent retry)
 7  /payment/<id>    secure (302 to login)
 8  /file/<id>       IDOR critical + path traversal flavour
 9  /slow/<id>       timeout handling
10  /missing/<id>    404 for all ids
11  /mixed/<id>      generic-200 with ONE id that differs in shape
"""

from __future__ import annotations

import time

from flask import Flask, jsonify, redirect, request

app = Flask(__name__)

INVOICES = {
    1: {"id": 1, "user_id": 101, "email": "alice@example.com", "phone": "+628111000101",
        "amount": 250, "item": "Keyboard"},
    2: {"id": 2, "user_id": 102, "email": "bob@example.com", "phone": "+628111000102",
        "amount": 120, "item": "Mouse"},
    3: {"id": 3, "user_id": 103, "email": "carol@example.com", "phone": "+628111000103",
        "amount": 90, "item": "Cable"},
}
ORDERS = {
    1: {"id": 1, "user_id": 101, "status": "shipped", "total": 42},
    2: {"id": 2, "user_id": 102, "status": "pending", "total": 17},
}
DOCS = {"welcome": "This is a generic document page. Nothing to see here."}
FILES = {
    1: {"id": 1, "user_id": 101, "name": "report-q1.pdf", "content": "Q1 financials: ok"},
    2: {"id": 2, "user_id": 102, "name": "salary-bob.txt", "content": "bob salary: secret"},
}
USERS = {
    "550e8400-e29b-41d4-a716-446655440000": {"uid": "550e8400-e29b-41d4-a716-446655440000",
                                              "email": "alice@example.com", "name": "Alice"},
    "7c9e6679-7425-40de-944b-e07fc1f90ae7": {"uid": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                                              "email": "bob@example.com", "name": "Bob"},
}


@app.get("/invoice/<int:inv_id>")
def invoice(inv_id: int):
    # VULNERABLE: no ownership check (eval case 1)
    inv = INVOICES.get(inv_id)
    if inv is None:
        return jsonify(error="not found"), 404
    return jsonify(inv)


@app.get("/orders/<int:order_id>")
def orders(order_id: int):
    # VULNERABLE: object data without PII (eval case 2)
    order = ORDERS.get(order_id)
    if order is None:
        return jsonify(error="not found"), 404
    return jsonify(order)


@app.get("/profile/<int:user_id>")
def profile(user_id: int):
    # SECURE: 403 unless your own id (eval case 3) — session cookie simulates
    # the authenticated owner of id 101.
    session_user = int(request.cookies.get("session_uid", "101"))
    if user_id != session_user:
        return jsonify(error="forbidden"), 403
    return jsonify({"id": user_id, "email": "alice@example.com"})


@app.get("/docs/<doc_id>")
def docs(doc_id: str):
    # GENERIC-200 TRAP (eval case 4): 200 for every id, even nonsense.
    return jsonify({"id": doc_id, "content": DOCS["welcome"]})


@app.get("/api/v2/user/<uid>")
def api_user(uid: str):
    # VULNERABLE uuid idor (eval case 5)
    user = USERS.get(uid)
    if user is None:
        return jsonify(error="not found"), 404
    return jsonify(user)


_FLAKY_N = 0


@app.get("/flaky/<int:obj_id>")
def flaky(obj_id: int):
    # AMBIGUOUS (eval case 6): every other request fails (inconsistent retry)
    global _FLAKY_N
    obj = INVOICES.get(obj_id)
    if obj is None:
        return jsonify(error="not found"), 404
    _FLAKY_N += 1
    if _FLAKY_N % 2 == 0:
        return jsonify(error="temporary failure"), 500
    return jsonify(obj)


@app.get("/payment/<int:pay_id>")
def payment(pay_id: int):
    # SECURE (eval case 7): redirects to login
    return redirect("/login")


@app.get("/file/<int:file_id>")
def file_download(file_id: int):
    # VULNERABLE (eval case 8): other users' files incl. private content
    f = FILES.get(file_id)
    if f is None:
        return jsonify(error="not found"), 404
    return jsonify(f)


@app.get("/slow/<int:obj_id>")
def slow(obj_id: int):
    # eval case 9: slow endpoint (scanner must handle timeout)
    time.sleep(30)
    return jsonify(ok=True)


@app.get("/missing/<int:obj_id>")
def missing(obj_id: int):
    # eval case 10: always 404
    return jsonify(error="not found"), 404


@app.get("/mixed/<mid>")
def mixed(mid: str):
    # eval case 11 (challenging): generic-200 for all ids BUT id "admin-panel"
    # returns a different shape — control-id + similarity must separate it.
    if mid == "admin-panel":
        return jsonify({"id": mid, "admin": True, "secret": "flag-internal"})
    return jsonify({"id": mid, "content": DOCS["welcome"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
