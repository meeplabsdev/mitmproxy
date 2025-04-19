import os

from flask import Flask
from flask import render_template

from mitmproxy import ctx
from mitmproxy.utils.magisk import write_magisk_module

app = Flask(__name__)
app.config["CONFDIR"] = ctx.options.confdir


@app.route("/")
def index():
    return render_template("index.html", ca_basename=ctx.options.ca_basename)


@app.route("/cert/pem")
def pem():
    return read_cert("pem", "application/x-x509-ca-cert")


@app.route("/cert/p12")
def p12():
    return read_cert("p12", "application/x-pkcs12")


@app.route("/cert/cer")
def cer():
    return read_cert("cer", "application/x-x509-ca-cert")


@app.route("/cert/magisk")
def magisk():
    filename = ctx.options.ca_basename + f"-magisk-module.zip"
    p = os.path.join(ctx.options.confdir, filename)
    p = os.path.expanduser(p)

    if not os.path.exists(p):
        write_magisk_module(p)

    with open(p, "rb") as f:
        cert = f.read()

    return cert, {
        "Content-Type": "application/zip",
        "Content-Disposition": f"attachment; filename={filename}",
    }


def read_cert(ext, content_type):
    filename = ctx.options.ca_basename + f"-ca-cert.{ext}"
    p = os.path.join(ctx.options.confdir, filename)
    p = os.path.expanduser(p)
    with open(p, "rb") as f:
        cert = f.read()

    return cert, {
        "Content-Type": content_type,
        "Content-Disposition": f"attachment; filename={filename}",
    }
