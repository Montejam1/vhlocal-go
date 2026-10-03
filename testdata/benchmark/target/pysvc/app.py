import os
import pickle
import sqlite3
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BASE = "/srv/exports"


def _conn():
    return sqlite3.connect("bench.db")


@app.route("/orders/search", methods=["GET"])
def search_orders():
    term = request.args.get("q", "")
    cur = _conn().cursor()
    cur.execute("SELECT id, total FROM orders WHERE customer LIKE '%" + term + "%'")
    return {"rows": cur.fetchall()}


@app.route("/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    cur = _conn().cursor()
    cur.execute("SELECT id, total FROM orders WHERE id = ?", (order_id,))
    return {"row": cur.fetchone()}


@app.route("/exports/download", methods=["GET"])
def download_export():
    name = request.args.get("name", "")
    return send_file(os.path.join(BASE, name))


@app.route("/exports/safe", methods=["GET"])
def download_export_safe():
    name = os.path.basename(request.args.get("name", ""))
    path = os.path.realpath(os.path.join(BASE, name))
    if not path.startswith(BASE + os.sep):
        abort(400)
    return send_file(path)


@app.route("/session/restore", methods=["POST"])
def restore_session():
    blob = request.get_data()
    state = pickle.loads(blob)
    return {"restored": bool(state)}


@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    cur = _conn().cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return {"deleted": user_id}


@app.route("/admin/users/<int:user_id>/safe", methods=["DELETE"])
def delete_user_safe(user_id):
    if request.headers.get("X-Role") != "admin":
        abort(403)
    cur = _conn().cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return {"deleted": user_id}
