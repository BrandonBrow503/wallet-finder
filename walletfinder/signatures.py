"""Known wallet signatures, filename patterns and default install paths.

Used by the scanner. Kept as plain data so it is easy to extend.
"""
from __future__ import annotations
import re

# Filename-based detectors. Each: (label, coin, regex on lowercase filename, confidence, note)
FILENAME_RULES = [
    ("Bitcoin Core wallet (wallet.dat)", "BTC", re.compile(r"^wallet(-.*)?\.dat$"), "high",
     "Bitcoin Core / Bitcoin-Qt wallet. Berkeley DB file. May be encrypted."),
    ("Core-fork wallet.dat (Litecoin/Dogecoin/etc.)", "ALT", re.compile(r".*wallet.*\.dat$"), "medium",
     "Looks like a Bitcoin-Core-style wallet.dat (could be Litecoin, Dogecoin, etc.)."),
    ("Electrum wallet", "BTC", re.compile(r"^(default_wallet|electrum.*|.*\.electrum)$"), "high",
     "Electrum wallet file. Often contains an encrypted seed."),
    ("MultiBit wallet", "BTC", re.compile(r".*\.(wallet|key)$"), "medium",
     "MultiBit / MultiBit HD wallet or key file."),
    ("Armory wallet", "BTC", re.compile(r".*armory.*\.wallet$"), "high",
     "Armory wallet file."),
    ("Blockchain.info backup", "BTC", re.compile(r"^wallet\.aes\.json$"), "high",
     "Blockchain.info wallet backup (AES-encrypted JSON)."),
    ("Ethereum keystore (UTC JSON)", "ETH", re.compile(r"^utc--.*"), "high",
     "Ethereum / Geth / MyEtherWallet keystore. Encrypted with a password."),
    ("Exodus wallet data", "MULTI", re.compile(r"^(exodus|seed\.seco|passphrase\.json)$"), "medium",
     "Exodus wallet data folder contents."),
    ("Jaxx wallet data", "MULTI", re.compile(r".*jaxx.*"), "low",
     "Possible Jaxx wallet data."),
    ("Bitcoin paper wallet (image/PDF)", "BTC", re.compile(r".*(paper.?wallet|bitcoin.?wallet).*\.(png|jpg|jpeg|pdf|bmp|gif)$"), "low",
     "Possible paper wallet image/PDF - open and look for printed keys/QRs."),
]

# Folder-name detectors: (label, coin, regex on lowercase dirname, note)
DIRNAME_RULES = [
    ("Bitcoin data directory", "BTC", re.compile(r"^bitcoin$"), "Default Bitcoin Core data dir - look inside for wallet.dat."),
    ("Litecoin data directory", "LTC", re.compile(r"^litecoin$"), "Default Litecoin Core data dir."),
    ("Dogecoin data directory", "DOGE", re.compile(r"^dogecoin$"), "Default Dogecoin Core data dir."),
    ("Electrum data directory", "BTC", re.compile(r"^electrum$"), "Electrum data dir - wallets/ inside."),
    ("Ethereum keystore directory", "ETH", re.compile(r"^keystore$"), "Geth/Mist/Ethereum keystore folder."),
    ("Exodus data directory", "MULTI", re.compile(r"^exodus$"), "Exodus wallet data folder."),
    ("Armory data directory", "BTC", re.compile(r"^armory$"), "Armory data folder."),
]

# Default wallet locations across OSes (shown in the Help screen; also used to prioritise scanning)
DEFAULT_PATHS = {
    "Windows XP": [
        r"Documents and Settings\<user>\Application Data\Bitcoin\wallet.dat",
        r"Documents and Settings\<user>\Application Data\Litecoin\wallet.dat",
        r"Documents and Settings\<user>\Application Data\Electrum\wallets\default_wallet",
    ],
    "Windows 7/8/10/11": [
        r"Users\<user>\AppData\Roaming\Bitcoin\wallet.dat",
        r"Users\<user>\AppData\Roaming\Litecoin\wallet.dat",
        r"Users\<user>\AppData\Roaming\DogeCoin\wallet.dat",
        r"Users\<user>\AppData\Roaming\Electrum\wallets\default_wallet",
        r"Users\<user>\AppData\Roaming\Exodus\ (folder)",
        r"Users\<user>\AppData\Roaming\Ethereum\keystore\ (folder)",
    ],
    "macOS": [
        "~/Library/Application Support/Bitcoin/wallet.dat",
        "~/Library/Application Support/Litecoin/wallet.dat",
        "~/Library/Application Support/Electrum/wallets/default_wallet",
        "~/Library/Ethereum/keystore/",
    ],
    "Linux": [
        "~/.bitcoin/wallet.dat",
        "~/.litecoin/wallet.dat",
        "~/.dogecoin/wallet.dat",
        "~/.electrum/wallets/default_wallet",
        "~/.ethereum/keystore/",
    ],
}

# Byte signatures for the raw / deleted-file scan.
# Each: (label, bytes pattern, confidence, note)
RAW_SIGNATURES = [
    ("Berkeley DB magic (wallet.dat)", b"\x62\x31\x05\x00", "medium",
     "Berkeley DB B-tree magic (0x00053162) - classic Bitcoin Core wallet.dat header."),
    ("Berkeley DB magic (byteswapped)", b"\x00\x05\x31\x62", "medium",
     "Berkeley DB magic, other byte order."),
    ("wallet.dat 'main' record", b"\x04name", "low", "Berkeley DB key record 'name' (address book)."),
    ("wallet.dat master key record", b"\x04mkey", "high",
     "'mkey' record means the wallet is ENCRYPTED (you will need its password)."),
    ("wallet.dat encrypted key", b"\x04ckey", "high",
     "'ckey' = encrypted private key - this wallet is password protected."),
    ("wallet.dat plain key", b"\x03key", "high",
     "'key' record - an UNencrypted private key may be present."),
    ("Ethereum keystore JSON", b'"crypto"', "low", "Possible Ethereum keystore JSON fragment."),
    ("MyEtherWallet/keystore cipher", b'"ciphertext"', "low", "Keystore cipher field."),
    ("Electrum seed marker", b'"seed_version"', "medium", "Electrum wallet JSON fragment."),
    ("Blockchain.info backup", b"wallet.aes.json", "low", "Blockchain.info backup reference."),
]

# Text-scan: patterns for loose keys inside text/document files.
# WIF: base58, starts 5 (uncompressed) or K/L (compressed) for BTC mainnet.
WIF_RE = re.compile(rb"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
# Litecoin WIF starts with 6 or T; Dogecoin with 6 or Q. We validate by checksum anyway.
ALT_WIF_RE = re.compile(rb"\b[6QT][1-9A-HJ-NP-Za-km-z]{50,51}\b")
XPRV_RE = re.compile(rb"\b(xprv|yprv|zprv|Ltpv|dgpv)[1-9A-HJ-NP-Za-km-z]{100,115}\b")
HEX64_RE = re.compile(rb"\b[0-9a-fA-F]{64}\b")
# BIP39 candidate: a run of 12/15/18/21/24 lowercase words
WORDS_RE = re.compile(rb"\b(?:[a-z]{3,8}[ \n\t,]+){11,23}[a-z]{3,8}\b")
EXTENSIONS_TEXT = {".txt", ".text", ".md", ".rtf", ".csv", ".log", ".json",
                   ".html", ".htm", ".xml", ".ini", ".cfg", ".note", ".doc",
                   ".rtf", ".eml", ".bak", ""}
