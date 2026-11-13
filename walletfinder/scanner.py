"""Read-only scanner for forgotten crypto wallets and keys.

Design rules:
  * Opens every file read-only ('rb'). Never writes to the scanned drive.
  * Works on any folder/drive the OS has mounted (FAT16/FAT32/exFAT/NTFS,
    and HFS+/ext via the OS; raw/image scanning via raw byte signatures).
  * Reports findings with type, location, confidence, and encryption status.
Nothing here can send, sweep or move coins.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict

from . import crypto
from . import signatures as sig


@dataclass
class Finding:
    kind: str                 # wallet type / what it is
    coin: str                 # BTC / ETH / LTC / DOGE / ALT / MULTI
    location: str             # file path or "image:offset"
    confidence: str           # high / medium / low
    encrypted: bool | None = None   # True/False/None(unknown)
    note: str = ""
    detail: str = ""          # extra technical detail
    secret: str = ""          # masked by GUI: WIF/seed/xprv if recovered (local only)
    secret_type: str = ""     # "wif" / "seed" / "xprv" / ""
    addresses: list = field(default_factory=list)  # derived/public addresses
    size: int = 0

    def to_dict(self):
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# File-level scan
# ---------------------------------------------------------------------------

def _is_probably_text(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in sig.EXTENSIONS_TEXT:
        return True
    return False


def _read_head(path: str, n: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def _wallet_dat_encrypted(path: str) -> bool | None:
    """Inspect a Berkeley-DB wallet.dat for mkey/ckey (encrypted) vs plain key."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(8 * 1024 * 1024)
    except OSError:
        return None
    if b"\x04mkey" in data or b"\x04ckey" in data:
        return True
    if b"\x03key" in data or b"\x04name" in data:
        return False
    return None


def classify_file(path: str):
    """Return a list of Findings for a single file (filename + content checks)."""
    out = []
    name = os.path.basename(path).lower()
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0

    parent = os.path.basename(os.path.dirname(path)).lower()
    _COIN_DIRS = {"litecoin": "LTC", "dogecoin": "DOGE", "doge": "DOGE",
                  "dash": "ALT", "bitcoin": "BTC"}
    # filename rules
    for label, coin, rx, conf, note in sig.FILENAME_RULES:
        if rx.match(name):
            enc = None
            detail = ""
            if "wallet.dat" in label.lower() or name.endswith(".dat"):
                enc = _wallet_dat_encrypted(path)
                if enc is True:
                    detail = "Encrypted (mkey/ckey present) - you will need the wallet password."
                elif enc is False:
                    detail = "No master-key record seen - may be an unencrypted wallet."
                # relabel by the parent folder (Litecoin/Dogecoin/... Core forks)
                if parent in _COIN_DIRS and parent != "bitcoin":
                    coin = _COIN_DIRS[parent]
                    label = f"{parent.capitalize()} Core wallet (wallet.dat)"
            out.append(Finding(kind=label, coin=coin, location=path, confidence=conf,
                               encrypted=enc, note=note, detail=detail, size=size))
            break  # one filename rule per file is enough

    # Ethereum keystore: parse the address field (public) without the password
    if name.startswith("utc--") or (name.endswith(".json") and size < 20000):
        addr = _eth_keystore_address(path)
        if addr:
            out.append(Finding(kind="Ethereum keystore (UTC JSON)", coin="ETH",
                               location=path, confidence="high", encrypted=True,
                               note="Encrypted Ethereum keystore - needs its password.",
                               detail=f"Public address: {addr}", addresses=[{"coin": "ETH", "address": addr}],
                               size=size))

    # content scan for loose keys/seeds in text-ish files
    if _is_probably_text(path) and 0 < size <= 5 * 1024 * 1024:
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
            out.extend(scan_text_blob(blob, path))
        except OSError:
            pass
    return out


def _eth_keystore_address(path: str):
    try:
        with open(path, "rb") as fh:
            obj = json.loads(fh.read().decode("utf-8", "ignore"))
    except Exception:
        return None
    if isinstance(obj, dict) and "crypto" in obj or "Crypto" in (obj or {}):
        addr = obj.get("address")
        if addr:
            a = addr if addr.startswith("0x") else "0x" + addr
            return crypto.eth_checksum(a)
    return None


# ---------------------------------------------------------------------------
# Loose-key text scan (shared by file scan and raw scan)
# ---------------------------------------------------------------------------

def scan_text_blob(blob: bytes, location: str):
    out = []
    seen = set()

    for rx in (sig.WIF_RE, sig.ALT_WIF_RE):
        for m in rx.finditer(blob):
            cand = m.group().decode("ascii", "ignore")
            if cand in seen:
                continue
            res = crypto.wif_to_priv(cand)
            if res is None:
                continue
            seen.add(cand)
            priv, comp, coin = res
            coin = coin or "BTC"
            addrs = _addresses_for_priv(priv, comp, coin)
            out.append(Finding(kind=f"Private key (WIF, {coin})", coin=coin, location=location,
                               confidence="high", encrypted=False,
                               note="A valid Wallet-Import-Format private key (checksum OK).",
                               secret=cand, secret_type="wif", addresses=addrs))

    for m in sig.XPRV_RE.finditer(blob):
        cand = m.group().decode("ascii", "ignore")
        if cand in seen:
            continue
        if crypto.b58check_decode(cand) is None:
            continue
        seen.add(cand)
        out.append(Finding(kind="Extended private key (xprv)", coin="BTC", location=location,
                           confidence="high", encrypted=False,
                           note="A BIP32 extended private master/child key (checksum OK).",
                           secret=cand, secret_type="xprv"))

    # BIP39 seed phrases: scan runs of lowercase words and slide valid-length
    # windows (12/15/18/21/24) so a phrase embedded in other text is still found.
    wordset = crypto.bip39_wordset()
    for m in re.finditer(rb"(?:[a-z]{3,8}[ \n\r\t,]+){10,40}[a-z]{3,8}", blob):
        toks = re.split(rb"[ \n\r\t,]+", m.group())
        words = [t.decode("ascii", "ignore") for t in toks if t]
        # only bother where most tokens are real BIP39 words
        hits = [w in wordset for w in words]
        if sum(hits) < 12:
            continue
        for length in (24, 21, 18, 15, 12):
            for start in range(0, len(words) - length + 1):
                window = words[start:start + length]
                if not all(w in wordset for w in window):
                    continue
                phrase = " ".join(window)
                if phrase in seen:
                    continue
                if crypto.bip39_validate(phrase):
                    seen.add(phrase)
                    addrs = _addresses_for_seed(crypto.bip39_seed(phrase))
                    out.append(Finding(kind=f"BIP39 seed phrase ({length} words)", coin="BTC",
                                       location=location, confidence="high", encrypted=False,
                                       note="A valid BIP39 recovery phrase (wordlist + checksum OK).",
                                       secret=phrase, secret_type="seed", addresses=addrs))

    # low-confidence raw hex (only flag if it looks deliberately isolated)
    hexmatches = sig.HEX64_RE.findall(blob)
    if hexmatches and len(blob) < 100000:
        uniq = set(h.decode() for h in hexmatches)
        for h in list(uniq)[:5]:
            iv = int(h, 16)
            if 0 < iv < crypto._N:
                out.append(Finding(kind="Possible raw hex private key (64 hex)", coin="BTC",
                                   location=location, confidence="low", encrypted=False,
                                   note="A 64-char hex string that is a valid secp256k1 scalar. "
                                        "Could be a private key - or just random data.",
                                   secret=h, secret_type="hex"))
    return out


def _addresses_for_priv(priv: bytes, compressed: bool, coin: str):
    out = []
    try:
        pub = crypto.pubkey_from_priv(priv, compressed)
        if coin in crypto.COIN_PARAMS:
            out.append({"coin": coin, "address": crypto.p2pkh_address(pub, coin), "kind": "legacy"})
            if coin == "BTC":
                out.append({"coin": coin, "address": crypto.p2sh_p2wpkh_address(pub, coin), "kind": "p2sh-segwit"})
                bech = crypto.p2wpkh_address(pub, coin)
                if bech:
                    out.append({"coin": coin, "address": bech, "kind": "native-segwit"})
        # also an ETH address from the same scalar (useful if it was an ETH key)
        out.append({"coin": "ETH", "address": crypto.eth_address_from_priv(priv), "kind": "ethereum"})
    except Exception:
        pass
    return out


def _addresses_for_seed(seed: bytes, count: int = 20):
    out = []
    for coin in ("BTC", "LTC", "DOGE"):
        try:
            out.extend(crypto.derive_addresses_from_seed(seed, coin, count))
        except Exception:
            pass
    # ETH from BIP44 path m/44'/60'/0'/0/0..
    try:
        for i in range(count):
            priv = crypto.derive_path(seed, f"m/44'/60'/0'/0/{i}")
            out.append({"coin": "ETH", "address": crypto.eth_address_from_priv(priv),
                        "kind": "ethereum", "path": f"m/44'/60'/0'/0/{i}"})
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Folder walk (file-level scan)
# ---------------------------------------------------------------------------

def scan_folder(root: str, progress=None, stop=None, max_file_mb: int = 50):
    """Walk a folder/drive read-only and yield Findings.

    progress(callback): called with (path, count) for UI updates.
    stop(callable): return True to abort early.
    """
    findings = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        if stop and stop():
            break
        # folder-name detectors
        base = os.path.basename(dirpath).lower()
        for label, coin, rx, note in sig.DIRNAME_RULES:
            if rx.match(base):
                findings.append(Finding(kind=label, coin=coin, location=dirpath,
                                        confidence="medium", note=note))
        for fn in filenames:
            if stop and stop():
                break
            path = os.path.join(dirpath, fn)
            scanned += 1
            if progress and scanned % 50 == 0:
                progress(path, scanned, len(findings))
            try:
                if os.path.islink(path):
                    continue
                if os.path.getsize(path) > max_file_mb * 1024 * 1024:
                    # too big to text-scan; still check filename rules cheaply
                    for res in classify_file_nameonly(path):
                        findings.append(res)
                    continue
            except OSError:
                continue
            try:
                findings.extend(classify_file(path))
            except Exception:
                continue
    if progress:
        progress(root, scanned, len(findings))
    return findings


def classify_file_nameonly(path: str):
    out = []
    name = os.path.basename(path).lower()
    size = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        pass
    for label, coin, rx, conf, note in sig.FILENAME_RULES:
        if rx.match(name):
            out.append(Finding(kind=label, coin=coin, location=path, confidence=conf,
                               note=note + " (large file - content not text-scanned)", size=size))
            break
    return out


# ---------------------------------------------------------------------------
# Raw / deleted-file scan (disk images or raw devices)
# ---------------------------------------------------------------------------

def scan_raw_image(path, progress=None, stop=None, chunk_mb: int = 8):
    """Scan a raw disk image or device for wallet byte-signatures & loose keys.

    Reads in overlapping chunks so patterns on chunk boundaries are caught.
    Read-only. Works on .img/.dd files and (with permission) raw devices.
    """
    findings = []
    overlap = 4096
    chunk = chunk_mb * 1024 * 1024
    try:
        total = os.path.getsize(path)
    except OSError:
        total = 0
    try:
        fh = open(path, "rb")
    except OSError as e:
        raise RuntimeError(f"Could not open {path}: {e}")
    seen_sig = set()
    with fh:
        pos = 0
        prev_tail = b""
        while True:
            if stop and stop():
                break
            data = fh.read(chunk)
            if not data:
                break
            window = prev_tail + data
            base_off = pos - len(prev_tail)
            # byte signatures
            for label, pat, conf, note in sig.RAW_SIGNATURES:
                start = 0
                while True:
                    idx = window.find(pat, start)
                    if idx == -1:
                        break
                    abs_off = base_off + idx
                    key = (label, abs_off)
                    bucket = abs_off // 65536
                    dedup = (label, bucket)
                    if dedup not in seen_sig:
                        seen_sig.add(dedup)
                        findings.append(Finding(
                            kind=f"Raw signature: {label}", coin="BTC",
                            location=f"{path} @ offset {abs_off} (0x{abs_off:x})",
                            confidence=conf,
                            encrypted=True if "mkey" in label or "ckey" in label else None,
                            note=note,
                            detail="Found by raw byte scan - may be a live or DELETED wallet remnant."))
                    start = idx + 1
            # loose keys in the raw bytes
            for f in scan_text_blob(window, f"{path} (raw scan near offset {base_off})"):
                findings.append(f)
            prev_tail = data[-overlap:]
            pos += len(data)
            if progress and total:
                progress(path, pos, len(findings), total)
    return findings


# ---------------------------------------------------------------------------
# pytsk3 (optional) - walk filesystems in an image incl. deleted entries
# ---------------------------------------------------------------------------

def tsk_available() -> bool:
    try:
        import pytsk3  # noqa
        return True
    except Exception:
        return False
