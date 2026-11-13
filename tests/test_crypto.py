"""Crypto correctness against published BIP test vectors."""
from walletfinder import crypto as c

M = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_keccak_empty():
    assert c.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_ripemd160():
    assert c._ripemd160_py(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert c.ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"


def test_hash160_empty():
    assert c.hash160(b"").hex() == "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"


def test_bip39_seed_vector():
    seed = c.bip39_seed(M, "TREZOR")
    assert seed.hex() == ("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e534955"
                          "31f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")


def test_bip84_native_segwit_vector():
    seed = c.bip39_seed(M, "")
    priv = c.derive_path(seed, "m/84'/0'/0'/0/0")
    pub = c.pubkey_from_priv(priv, True)
    assert c.p2wpkh_address(pub) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_wif_roundtrip_and_vector():
    k = b"\x00" * 31 + b"\x01"
    wif = c.priv_to_wif(k, True)
    assert wif == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    priv, comp, coin = c.wif_to_priv(wif)
    assert priv == k and comp is True and coin == "BTC"


def test_wif_bad_checksum_rejected():
    assert c.wif_to_priv("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWX") is None


def test_eth_address_vector():
    k = b"\x00" * 31 + b"\x01"
    assert c.eth_address_from_priv(k).lower() == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"


def test_eth_checksum_vector():
    assert c.eth_checksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed") == \
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def test_bip39_validate():
    assert c.bip39_validate(M) is True
    assert c.bip39_validate("abandon " * 11 + "abandon") is False
    assert c.bip39_validate("not real words here at all nope nope nope nope nope nope nope") is False


def test_derive_addresses_count():
    seed = c.bip39_seed(M, "")
    addrs = c.derive_addresses_from_seed(seed, "BTC", 5)
    # 3 schemes x 5 addresses
    assert len(addrs) == 15
    assert all(a["address"] for a in addrs)
    # DOGE has no bech32, so only 2 schemes
    daddrs = c.derive_addresses_from_seed(seed, "DOGE", 5)
    assert len(daddrs) == 10


def test_ltc_doge_wif_prefixes():
    k = b"\x11" * 32
    assert c.priv_to_wif(k, True, "LTC")[0] == "T"
    # roundtrip coin detection
    wif = c.priv_to_wif(k, True, "LTC")
    assert c.wif_to_priv(wif)[2] == "LTC"
