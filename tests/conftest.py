"""Shared fixtures build small repository targets without local data dependencies."""

import pytest

_FLASK_APP = """
from flask import Flask, request
app = Flask(__name__)

@app.route("/wallets/<wallet_id>", methods=["GET"])
def get_wallet(wallet_id):
    return request.args.get("x", "")

@app.route("/transfers", methods=["POST"])
def create_transfer():
    return "", 201
"""


@pytest.fixture
def custody_repository(tmp_path):
    """A tiny Flask app seeds a stable workspace path for engine tests."""
    d = tmp_path / "custody"
    (d / "app" / "services").mkdir(parents=True)
    (d / "app" / "routes.py").write_text(_FLASK_APP)
    (d / "app" / "services" / "wallet.py").write_text("def get_wallet(wid):\n    return {'id': wid}\n")
    (d / "requirements.txt").write_text("Flask==3.0\n")
    return d
