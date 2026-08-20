import os

INVOICE_DIR = "/srv/invoices"

def _invoice_path(name):
    return os.path.join(INVOICE_DIR, name)

def fetch_invoice(name):
    path = _invoice_path(name)
    with open(path, "rb") as fh:
        return fh.read()

def render_invoice(src):
    out = "/tmp/out.pdf"
    cmd = "wkhtmltopdf " + src + " " + out
    os.system(cmd)
    with open(out, "rb") as fh:
        return fh.read()
