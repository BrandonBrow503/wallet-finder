"""Report export + masking tests (local only, no network)."""
import json
import os

from walletfinder import report
from walletfinder.scanner import Finding


def _sample():
    return [
        Finding(kind="Private key (WIF, BTC)", coin="BTC", location="/x/notes.txt",
                confidence="high", encrypted=False, secret="KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
                secret_type="wif", addresses=[{"coin": "BTC", "address": "1abc", "kind": "legacy"}]),
        Finding(kind="Bitcoin Core wallet (wallet.dat)", coin="BTC", location="/x/wallet.dat",
                confidence="high", encrypted=True, note="encrypted"),
    ]


def test_mask():
    assert report._mask("L3pr5wQW9YhGyNJJPB59ZZaniFFUzXF") == "L3pr…zXFu"[:4] + "…" + "L3pr5wQW9YhGyNJJPB59ZZaniFFUzXF"[-4:]
    assert "…" in report._mask("abcdefghijklmnop")


def test_export_json_masks_by_default(tmp_path):
    p = os.path.join(tmp_path, "r.json")
    report.export_json(_sample(), p, include_secrets=False)
    data = json.load(open(p))
    secret = [f for f in data["findings"] if f["secret_type"] == "wif"][0]["secret"]
    assert "…" in secret
    assert "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn" != secret


def test_export_json_reveal(tmp_path):
    p = os.path.join(tmp_path, "r.json")
    report.export_json(_sample(), p, include_secrets=True)
    data = json.load(open(p))
    secret = [f for f in data["findings"] if f["secret_type"] == "wif"][0]["secret"]
    assert secret == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"


def test_export_html_and_text(tmp_path):
    ph = os.path.join(tmp_path, "r.html")
    pt = os.path.join(tmp_path, "r.txt")
    report.export_html(_sample(), ph, include_secrets=False, balances_total=1234.56)
    report.export_text(_sample(), pt, include_secrets=False)
    html = open(ph).read()
    assert "Wallet Finder" in html and "$1,234.56" in html
    assert "return them" in html.lower()
    txt = open(pt).read()
    assert "RECOVERY REPORT" in txt


def test_copy_to_safe_folder(tmp_path):
    src = os.path.join(tmp_path, "wallet.dat")
    open(src, "wb").write(b"hello")
    dest = os.path.join(tmp_path, "safe")
    out = report.copy_to_safe_folder(src, dest)
    assert os.path.exists(out) and open(out, "rb").read() == b"hello"
    # second copy should not overwrite
    out2 = report.copy_to_safe_folder(src, dest)
    assert out != out2
