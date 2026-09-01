"""Sample vulnerable SQL-injection module for mode=program scans (SQLI rules).

Expected SQLi rule hits:
  * SQLI001 — cursor.execute(f"...") in query_orders
  * SQLI001 — cursor.execute("SELECT ... %s" % ...) in query_users
  * SQLI002 — Django Model.objects.raw(f"...") in raw_invoices
  * SQLI003 — SQLAlchemy text(f"...") in search_products
  * SQLI006 — raw f-string SQL assignment in build_sql
"""

from __future__ import annotations


def query_orders(conn, order_id):
    # SQLI001: f-string interpolated into execute()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    return cur.fetchall()


def query_users(conn, user_id):
    # SQLI001: %-formatting into execute()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}" )
    return cur.fetchall()


def safe_query(conn, user_id):
    # SAFE: parameterized query — must NOT be flagged
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cur.fetchall()


def raw_invoices(uid):
    # SQLI002: Django raw() with f-string
    from django.db import models  # noqa: F401

    class Invoice(models.Model):  # noqa: D101
        pass

    return Invoice.objects.raw(f"SELECT * FROM invoices WHERE user_id = {uid}")


def search_products(term):
    # SQLI003: SQLAlchemy text() with f-string
    from sqlalchemy import text  # noqa: F401

    return text(f"SELECT * FROM products WHERE name LIKE '%{term}%'")


def build_sql(user_input):
    # SQLI006: raw f-string SQL stored in a variable
    sql = f"SELECT secret FROM flags WHERE token = '{user_input}'"
    return sql
