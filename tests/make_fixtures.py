#!/usr/bin/env python3
"""Generate SYNTHETIC test fixtures with freshly generated throwaway keys.

NONE of these hold real funds. Keys are generated right here from os.urandom.
Creates:
  fixtures/drive/...            a fake 'drive' folder tree with wallet files
  fixtures/image_deleted.img    a raw image containing a 'deleted' wallet remnant
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from walletfinder import crypto

FX = os.path.join(HERE, "fixtures")


def w(path, data, mode="wb"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode) as fh:
        fh.write(data)


def fresh_priv():
    while True:
        p = os.urandom(32)
        if 0 < int.from_bytes(p, "big") < crypto._N:
            return p


def build():
    import shutil
    if os.path.exists(FX):
        shutil.rmtree(FX)
    os.makedirs(FX)

    manifest = {}

    # --- a WIF private key in a loose text file ---
    priv = fresh_priv()
    wif = crypto.priv_to_wif(priv, True, "BTC")
    addr = crypto.p2pkh_address(crypto.pubkey_from_priv(priv, True), "BTC")
    w(os.path.join(FX, "drive", "Documents", "old_notes.txt"),
      (f"my backup from 2013\nbitcoin key: {wif}\n(do not lose!)\n").encode())
    manifest["wif"] = {"wif": wif, "address": addr}

    # --- a BIP39 seed phrase in a text file (fresh 12-word) ---
    ent = os.urandom(16)
    from mnemonic import Mnemonic
    phrase = Mnemonic("english").to_mnemonic(ent)
    assert crypto.bip39_validate(phrase)
    w(os.path.join(FX, "drive", "seed_backup.txt"),
      (f"RECOVERY WORDS - keep safe\n\n{phrase}\n").encode())
    manifest["seed"] = phrase

    # --- an Electrum-like wallet file ---
    electrum = {
        "seed_version": 18,
        "wallet_type": "standard",
        "use_encryption": False,
        "keystore": {"type": "bip32", "xpub": "xpub-fake-public-only"},
    }
    w(os.path.join(FX, "drive", "AppData", "Roaming", "Electrum", "wallets", "default_wallet"),
      json.dumps(electrum, indent=1).encode())
    manifest["electrum"] = "default_wallet"

    # --- an Ethereum keystore JSON (UTC--...), fresh address ---
    epriv = fresh_priv()
    eaddr = crypto.eth_address_from_priv(epriv)[2:].lower()
    keystore = {
        "address": eaddr,
        "crypto": {
            "cipher": "aes-128-ctr",
            "ciphertext": os.urandom(32).hex(),
            "cipherparams": {"iv": os.urandom(16).hex()},
            "kdf": "scrypt",
            "kdfparams": {"salt": os.urandom(32).hex(), "n": 262144, "r": 8, "p": 1, "dklen": 32},
            "mac": os.urandom(32).hex(),
        },
        "id": "00000000-0000-0000-0000-000000000000",
        "version": 3,
    }
    w(os.path.join(FX, "drive", "Ethereum", "keystore", "UTC--2018-01-01T00-00-00.0Z--" + eaddr),
      json.dumps(keystore).encode())
    manifest["eth_keystore"] = {"address": crypto.eth_checksum("0x" + eaddr)}

    # --- a fake Bitcoin Core wallet.dat with BDB magic + key records (ENCRYPTED) ---
    bdb = bytearray(4096)
    # Berkeley DB B-tree magic 0x00053162 at offset 12 (little-endian in file)
    struct.pack_into("<I", bdb, 12, 0x00053162)
    body = bytes(bdb)
    body += b"\x04name" + os.urandom(20)
    body += b"\x04mkey" + os.urandom(48)      # mkey => encrypted
    body += b"\x04ckey" + os.urandom(48)      # encrypted private key
    w(os.path.join(FX, "drive", "AppData", "Roaming", "Bitcoin", "wallet.dat"), body)
    manifest["wallet_dat"] = {"encrypted": True}

    # --- an UNencrypted-looking wallet.dat too ---
    bdb2 = bytearray(4096)
    struct.pack_into("<I", bdb2, 12, 0x00053162)
    body2 = bytes(bdb2) + b"\x04name" + os.urandom(20) + b"\x03key" + os.urandom(32)
    w(os.path.join(FX, "drive", "Litecoin", "wallet.dat"), body2)
    manifest["ltc_wallet_dat"] = {"encrypted": False}

    # --- a raw disk image with a 'deleted' wallet remnant in unallocated space ---
    img = bytearray(6 * 1024 * 1024)        # 6 MB of zeros = 'free space'
    # simulate a deleted wallet.dat whose directory entry is gone but data remains
    remnant = bytearray(8192)
    struct.pack_into("<I", remnant, 12, 0x00053162)
    remnant[1000:1000+5] = b"\x04mkey"
    remnant[2000:2000+4] = b"\x03key"
    img[1024*1024:1024*1024+len(remnant)] = remnant
    # a loose WIF key floating in free space (fresh)
    dpriv = fresh_priv()
    dwif = crypto.priv_to_wif(dpriv, True, "BTC")
    off = 3 * 1024 * 1024
    img[off:off+len(dwif)] = dwif.encode()
    w(os.path.join(FX, "image_deleted.img"), bytes(img))
    manifest["image"] = {"deleted_wif": dwif,
                         "deleted_wif_address": crypto.p2pkh_address(crypto.pubkey_from_priv(dpriv, True))}

    # --- a decoy: a random 64-hex that is NOT a key context + a non-wallet .dat ---
    w(os.path.join(FX, "drive", "random", "data.dat"), os.urandom(2048))
    w(os.path.join(FX, "drive", "random", "readme.txt"), b"just some notes, nothing to see")

    with open(os.path.join(FX, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    print("Fixtures written to", FX)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    build()
