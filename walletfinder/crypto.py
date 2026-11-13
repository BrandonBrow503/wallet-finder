"""Pure-Python crypto helpers (no compiled deps, so the Windows build stays simple).

Everything here runs locally. Nothing in this module touches the network.
Implements: base58check, bech32/segwit, secp256k1 point math, hash160, WIF,
BIP32/BIP39/BIP44/49/84 derivation, keccak-256 and Ethereum addresses.
"""
from __future__ import annotations

import hashlib
import hmac
import struct


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b))


def _ripemd160_py(msg: bytes) -> bytes:
    r1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    r2 = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    s1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    s2 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    K1 = [0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E]
    K2 = [0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000]
    M = 0xFFFFFFFF

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & M

    def f(j, x, y, z):
        if j < 16: return x ^ y ^ z
        if j < 32: return (x & y) | (~x & M & z)
        if j < 48: return (x | (~y & M)) ^ z
        if j < 64: return (x & z) | (y & ~z & M)
        return x ^ (y | (~z & M))

    h = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
    ml = len(msg) * 8
    msg = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + struct.pack("<Q", ml)
    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[off:off + 64])
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = (rol((al + f(j, bl, cl, dl) + X[r1[j]] + K1[j // 16]) & M, s1[j]) + el) & M
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (rol((ar + f(79 - j, br, cr, dr) + X[r2[j]] + K2[j // 16]) & M, s2[j]) + er) & M
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h[1] + cl + dr) & M
        h[1] = (h[2] + dl + er) & M
        h[2] = (h[3] + el + ar) & M
        h[3] = (h[4] + al + br) & M
        h[4] = (h[0] + bl + cr) & M
        h[0] = t
    return struct.pack("<5I", *h)


def ripemd160(b: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", b).digest()
    except (ValueError, TypeError):
        return _ripemd160_py(b)


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]


def keccak256(data: bytes) -> bytes:
    M64 = (1 << 64) - 1
    rate = 136
    st = [[0] * 5 for _ in range(5)]
    data = bytearray(data)
    data.append(0x01)
    while len(data) % rate:
        data.append(0)
    data[-1] |= 0x80

    def rot(v, n):
        return ((v << n) | (v >> (64 - n))) & M64 if n else v

    for off in range(0, len(data), rate):
        block = data[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            st[x][y] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        for rnd in range(24):
            C = [st[x][0] ^ st[x][1] ^ st[x][2] ^ st[x][3] ^ st[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ rot(C[(x + 1) % 5], 1) for x in range(5)]
            st = [[st[x][y] ^ D[x] for y in range(5)] for x in range(5)]
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    B[y][(2 * x + 3 * y) % 5] = rot(st[x][y], _KECCAK_ROT[x][y])
            st = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            st[0][0] ^= _KECCAK_RC[rnd]
    out = b""
    for i in range(4):
        x, y = i % 5, i // 5
        out += st[x][y].to_bytes(8, "little")
    return out


# --------------------------------------------------------------------------
# Base58 / Bech32
# --------------------------------------------------------------------------
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c: i for i, c in enumerate(B58)}


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58_IDX:
            raise ValueError("bad base58 char")
        n = n * 58 + _B58_IDX[c]
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + full


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + dsha256(payload)[:4])


def b58check_decode(s: str):
    try:
        raw = b58decode(s)
    except ValueError:
        return None
    if len(raw) < 5:
        return None
    payload, chk = raw[:-4], raw[-4:]
    if dsha256(payload)[:4] != chk:
        return None
    return payload


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        return None
    return ret


def segwit_encode(hrp: str, witver: int, prog: bytes) -> str:
    const = 1 if witver == 0 else 0x2BC830A3
    data = [witver] + _convertbits(prog, 8, 5)
    values = _hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0] * 6) ^ const
    chk = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + chk)


# --------------------------------------------------------------------------
# secp256k1
# --------------------------------------------------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a, n):
    return pow(a, n - 2, n)


def _pt_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p == q:
        m = (3 * x1 * x1) * _inv(2 * y1, _P) % _P
    else:
        m = (y2 - y1) * _inv((x2 - x1) % _P, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    y3 = (m * (x1 - x3) - y1) % _P
    return (x3, y3)


def _pt_mul(k, p=(_Gx, _Gy)):
    r = None
    while k:
        if k & 1:
            r = _pt_add(r, p)
        p = _pt_add(p, p)
        k >>= 1
    return r


def pubkey_from_priv(priv: bytes, compressed: bool = True) -> bytes:
    k = int.from_bytes(priv, "big") % _N
    x, y = _pt_mul(k)
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# --------------------------------------------------------------------------
# Addresses
# --------------------------------------------------------------------------
# Version bytes per coin: (p2pkh, p2sh, wif, bech32_hrp)
COIN_PARAMS = {
    "BTC": (0x00, 0x05, 0x80, "bc"),
    "LTC": (0x30, 0x32, 0xB0, "ltc"),
    "DOGE": (0x1E, 0x16, 0x9E, None),
}


def p2pkh_address(pubkey: bytes, coin: str = "BTC") -> str:
    ver = COIN_PARAMS[coin][0]
    return b58check_encode(bytes([ver]) + hash160(pubkey))


def p2sh_p2wpkh_address(pubkey: bytes, coin: str = "BTC") -> str:
    """P2SH-wrapped segwit (addresses starting with 3 for BTC)."""
    wpkh = hash160(pubkey)
    redeem = b"\x00\x14" + wpkh
    ver = COIN_PARAMS[coin][1]
    return b58check_encode(bytes([ver]) + hash160(redeem))


def p2wpkh_address(pubkey: bytes, coin: str = "BTC") -> str | None:
    hrp = COIN_PARAMS[coin][3]
    if hrp is None:
        return None
    return segwit_encode(hrp, 0, hash160(pubkey))


def eth_address_from_pub(pubkey_uncompressed: bytes) -> str:
    if pubkey_uncompressed[0] == 0x04:
        pubkey_uncompressed = pubkey_uncompressed[1:]
    h = keccak256(pubkey_uncompressed)
    addr = h[-20:]
    return eth_checksum("0x" + addr.hex())


def eth_checksum(addr: str) -> str:
    addr = addr.lower().replace("0x", "")
    h = keccak256(addr.encode()).hex()
    out = "0x"
    for i, c in enumerate(addr):
        out += c.upper() if (c.isalpha() and int(h[i], 16) >= 8) else c
    return out


def eth_address_from_priv(priv: bytes) -> str:
    pub = pubkey_from_priv(priv, compressed=False)
    return eth_address_from_pub(pub)


# --------------------------------------------------------------------------
# WIF
# --------------------------------------------------------------------------

def wif_to_priv(wif: str):
    """Returns (priv_bytes, compressed, coin) or None if invalid checksum."""
    payload = b58check_decode(wif)
    if payload is None:
        return None
    ver = payload[0]
    coin = None
    for name, params in COIN_PARAMS.items():
        if params[2] == ver:
            coin = name
            break
    body = payload[1:]
    if len(body) == 33 and body[-1] == 0x01:
        return body[:32], True, coin
    if len(body) == 32:
        return body, False, coin
    return None


def priv_to_wif(priv: bytes, compressed: bool = True, coin: str = "BTC") -> str:
    ver = COIN_PARAMS[coin][2]
    body = bytes([ver]) + priv + (b"\x01" if compressed else b"")
    return b58check_encode(body)


# --------------------------------------------------------------------------
# BIP32 / BIP39 / BIP44
# --------------------------------------------------------------------------

def bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    import unicodedata
    m = unicodedata.normalize("NFKD", mnemonic)
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode(), salt.encode(), 2048, 64)


def bip32_master(seed: bytes):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]  # key, chaincode


def bip32_ckd_priv(k: bytes, c: bytes, index: int):
    if index & 0x80000000:
        data = b"\x00" + k + struct.pack(">I", index)
    else:
        data = pubkey_from_priv(k, True) + struct.pack(">I", index)
    I = hmac.new(c, data, hashlib.sha512).digest()
    ki = (int.from_bytes(I[:32], "big") + int.from_bytes(k, "big")) % _N
    return ki.to_bytes(32, "big"), I[32:]


def derive_path(seed: bytes, path: str):
    """path like m/44'/0'/0'/0/0 -> priv bytes."""
    k, c = bip32_master(seed)
    for part in path.split("/"):
        if part in ("m", ""):
            continue
        hard = part.endswith("'") or part.endswith("h")
        idx = int(part.rstrip("'h"))
        if hard:
            idx += 0x80000000
        k, c = bip32_ckd_priv(k, c, idx)
    return k


# --------------------------------------------------------------------------
# BIP39 wordlist + validation
# --------------------------------------------------------------------------
import os as _os

_WORDLIST = None


def _load_wordlist():
    global _WORDLIST
    if _WORDLIST is None:
        import sys as _sys
        candidates = [_os.path.join(_os.path.dirname(__file__), "data", "bip39_english.txt")]
        base = getattr(_sys, "_MEIPASS", None)
        if base:
            candidates.append(_os.path.join(base, "walletfinder", "data", "bip39_english.txt"))
            candidates.append(_os.path.join(base, "data", "bip39_english.txt"))
        for path in candidates:
            if _os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    _WORDLIST = [w.strip() for w in fh if w.strip()]
                break
        if _WORDLIST is None:
            raise FileNotFoundError("bip39_english.txt not found in: " + "; ".join(candidates))
    return _WORDLIST


def bip39_wordset():
    return set(_load_wordlist())


def bip39_validate(mnemonic: str) -> bool:
    words = mnemonic.split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    wl = _load_wordlist()
    idx = {w: i for i, w in enumerate(wl)}
    try:
        bits = "".join(format(idx[w], "011b") for w in words)
    except KeyError:
        return False
    ent_len = len(bits) * 32 // 33
    ent_bits, chk_bits = bits[:ent_len], bits[ent_len:]
    ent = int(ent_bits, 2).to_bytes(ent_len // 8, "big")
    h = bin(int.from_bytes(sha256(ent), "big"))[2:].zfill(256)
    return h[:len(chk_bits)] == chk_bits


def derive_addresses_from_seed(seed: bytes, coin: str = "BTC", count: int = 20):
    """Derive the first `count` receive addresses for BIP44/49/84 paths.

    Returns list of dicts: {path, address, kind, priv_wif}.
    """
    out = []
    coin_type = {"BTC": 0, "LTC": 2, "DOGE": 3}.get(coin, 0)
    schemes = [
        ("BIP44 (legacy)", 44, "p2pkh"),
        ("BIP49 (segwit-compat)", 49, "p2sh"),
        ("BIP84 (native segwit)", 84, "bech32"),
    ]
    for label, purpose, kind in schemes:
        if kind == "bech32" and COIN_PARAMS[coin][3] is None:
            continue
        for i in range(count):
            path = f"m/{purpose}'/{coin_type}'/0'/0/{i}"
            try:
                priv = derive_path(seed, path)
                pub = pubkey_from_priv(priv, True)
                if kind == "p2pkh":
                    addr = p2pkh_address(pub, coin)
                elif kind == "p2sh":
                    addr = p2sh_p2wpkh_address(pub, coin)
                else:
                    addr = p2wpkh_address(pub, coin)
                if addr is None:
                    continue
                out.append({
                    "path": path, "address": addr, "kind": label, "coin": coin,
                    "priv_wif": priv_to_wif(priv, True, coin),
                })
            except Exception:
                continue
    return out
