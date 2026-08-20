"""Order management API."""
from flask import Flask, request, jsonify, session
from app.db import find_orders, get_order_by_id, find_user_safe
from app.files import fetch_invoice, render_invoice

app = Flask(__name__)


@app.route("/api/search")
def search():
    # Customer-facing order search.
    term = request.args.get("q", "")
    status = request.args.get("status", "open")
    return jsonify(find_orders(term, status))


@app.route("/api/orders/<order_id>")
def get_order(order_id):
    # Authenticated endpoint.
    if "uid" not in session:
        return jsonify({"error": "auth required"}), 401
    return jsonify(get_order_by_id(order_id))


@app.route("/api/invoice")
def invoice():
    name = request.args.get("name", "")
    return fetch_invoice(name)


@app.route("/api/invoice/render")
def invoice_render():
    src = request.args.get("src", "")
    return render_invoice(src)


@app.route("/api/users")
def users():
    # Lookup by email.
    email = request.args.get("email", "")
    return jsonify(find_user_safe(email))
