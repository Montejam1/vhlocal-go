const express = require("express");
const escapeHtml = require("escape-html");
const app = express();

app.get("/greet", (req, res) => {
  const name = req.query.name || "";
  res.send("<h1>Hello " + name + "</h1>");
});

app.get("/greet/safe", (req, res) => {
  const name = req.query.name || "";
  res.send("<h1>Hello " + escapeHtml(name) + "</h1>");
});

app.post("/calc", (req, res) => {
  const expr = String(req.body.expr || "0");
  const value = eval(expr);
  res.json({ value });
});

app.post("/calc/safe", (req, res) => {
  const value = Number(req.body.expr);
  if (Number.isNaN(value)) return res.status(400).json({ error: "not a number" });
  res.json({ value });
});

app.get("/profile/:id", (req, res) => {
  res.json(db.profiles[req.params.id]);
});

app.get("/profile/:id/safe", (req, res) => {
  if (req.user.id !== req.params.id) return res.status(403).end();
  res.json(db.profiles[req.params.id]);
});

module.exports = app;
