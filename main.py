#!/usr/bin/env python3
"""Wallet Finder - entry point.

Recover crypto from your own old drives. Read-only. Never moves funds.
  python main.py             # launch the app
  python main.py --selftest  # verify the bundled crypto engine, then exit
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def selftest():
    from walletfinder import crypto
    M = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    assert crypto.keccak256(b"").hex().startswith("c5d24601")
    assert crypto.bip39_validate(M) is True
    seed = crypto.bip39_seed(M, "")
    pub = crypto.pubkey_from_priv(crypto.derive_path(seed, "m/84'/0'/0'/0/0"), True)
    assert crypto.p2wpkh_address(pub) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    k = b"\x00" * 31 + b"\x01"
    assert crypto.priv_to_wif(k, True) == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    assert crypto.eth_address_from_priv(k).lower() == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    print("SELFTEST OK: crypto engine + BIP39 wordlist loaded and correct.")


def main():
    if "--selftest" in sys.argv:
        selftest()
        return
    from walletfinder.gui.app import main as gui_main
    gui_main()


if __name__ == "__main__":
    main()
