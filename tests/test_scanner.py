"""Scanner tests against synthetic fixtures (generated fresh, no real funds)."""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from walletfinder import scanner

FX = os.path.join(HERE, "fixtures")


@pytest.fixture(scope="module", autouse=True)
def fixtures():
    if not os.path.exists(os.path.join(FX, "manifest.json")):
        subprocess.check_call([sys.executable, os.path.join(HERE, "make_fixtures.py")])
    with open(os.path.join(FX, "manifest.json")) as fh:
        return json.load(fh)


def _kinds(findings):
    return [f.kind for f in findings]


def test_file_scan_finds_wallet_dat_encrypted():
    res = scanner.scan_folder(os.path.join(FX, "drive"))
    dats = [f for f in res if "wallet.dat" in f.kind.lower() or "Core wallet" in f.kind]
    assert dats, "no wallet.dat found"
    assert any(f.encrypted is True for f in dats), "expected an encrypted wallet.dat"


def test_file_scan_finds_wif():
    res = scanner.scan_folder(os.path.join(FX, "drive"))
    wifs = [f for f in res if f.secret_type == "wif"]
    assert wifs, "no WIF found"
    assert wifs[0].addresses, "WIF should derive addresses"


def test_file_scan_finds_seed():
    res = scanner.scan_folder(os.path.join(FX, "drive"))
    seeds = [f for f in res if f.secret_type == "seed"]
    assert seeds, "no BIP39 seed found"
    # a 12-word seed derives many addresses across coins/paths
    assert len(seeds[0].addresses) > 20


def test_file_scan_finds_electrum():
    res = scanner.scan_folder(os.path.join(FX, "drive"))
    assert any("Electrum" in f.kind for f in res)


def test_file_scan_finds_eth_keystore(fixtures):
    res = scanner.scan_folder(os.path.join(FX, "drive"))
    eth = [f for f in res if f.coin == "ETH" and f.encrypted is True and f.addresses]
    assert eth, "no encrypted ETH keystore with address found"
    assert any(a["address"] == fixtures["eth_keystore"]["address"]
               for f in eth for a in f.addresses)


def test_raw_scan_finds_deleted_remnant(fixtures):
    res = scanner.scan_raw_image(os.path.join(FX, "image_deleted.img"))
    sigs = [f for f in res if "Raw signature" in f.kind]
    assert sigs, "raw scan found no signatures"
    assert any("master key" in f.kind for f in sigs), "should flag encrypted mkey remnant"
    # and it should recover the loose WIF floating in free space
    wifs = [f for f in res if f.secret_type == "wif"]
    assert wifs
    assert any(a["address"] == fixtures["image"]["deleted_wif_address"]
               for w in wifs for a in w.addresses)


def test_scan_is_readonly(tmp_path):
    # snapshot mtimes before and after; scanner must not modify anything
    import time
    target = os.path.join(FX, "drive")
    before = {}
    for dp, _, fns in os.walk(target):
        for fn in fns:
            p = os.path.join(dp, fn)
            before[p] = os.stat(p).st_mtime_ns
    scanner.scan_folder(target)
    for p, mt in before.items():
        assert os.stat(p).st_mtime_ns == mt, f"{p} was modified!"


def test_text_blob_rejects_random_hex():
    # random non-key text should not yield high-confidence findings
    res = scanner.scan_text_blob(b"the quick brown fox jumps over the lazy dog " * 5,
                                 "mem")
    assert all(f.confidence != "high" for f in res)
