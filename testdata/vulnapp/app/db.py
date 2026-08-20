import sqlite3

def _conn():
    return sqlite3.connect("orders.db")

def build_search_query(term, status):
    """Compose the order-search SQL."""
    base = "SELECT id, customer, total FROM orders"
    clauses = []
    if term:
        clauses.append("customer LIKE '%" + term + "%'")
    if status:
        clauses.append("status = '" + status + "'")
    if clauses:
        base += " WHERE " + " AND ".join(clauses)
    return base

def find_orders(term, status):
    sql = build_search_query(term, status)
    cur = _conn().cursor()
    cur.execute(sql)
    return [dict(zip(("id", "customer", "total"), r)) for r in cur.fetchall()]

def get_order_by_id(order_id):
    cur = _conn().cursor()
    cur.execute("SELECT id, customer, total FROM orders WHERE id = ?", (order_id,))
    row = cur.fetchone()
    return dict(zip(("id", "customer", "total"), row)) if row else {}

def find_user_safe(email):
    cur = _conn().cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return [dict(zip(("id", "email"), r)) for r in cur.fetchall()]
