#!/usr/bin/env python3
"""Headless render of the main screens to PNGs (for docs/preview)."""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from walletfinder.gui.app import WalletFinderApp
from walletfinder.scanner import Finding
from walletfinder import balance

OUT = HERE


def sample_findings():
    return [
        Finding(kind="Bitcoin Core wallet (wallet.dat)", coin="BTC",
                location=r"E:\AppData\Roaming\Bitcoin\wallet.dat", confidence="high",
                encrypted=True, note="Bitcoin Core / Bitcoin-Qt wallet. Berkeley DB file.",
                detail="Encrypted (mkey/ckey present) - you will need the wallet password.",
                addresses=[{"coin": "BTC", "address": "1BitcoinEaterAddressDontSendf59kuE", "kind": "legacy"}]),
        Finding(kind="BIP39 seed phrase (12 words)", coin="BTC",
                location=r"E:\Documents\seed_backup.txt", confidence="high", encrypted=False,
                note="A valid BIP39 recovery phrase (wordlist + checksum OK).",
                secret="witch collapse practice feed shame open despair creek road again ice least",
                secret_type="seed",
                addresses=[
                    {"coin": "BTC", "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "kind": "native-segwit", "path": "m/84'/0'/0'/0/0"},
                    {"coin": "BTC", "address": "1Q6saSi96kc5Pp5Mv1zjfxqHA6aEhfyXaM", "kind": "legacy", "path": "m/44'/0'/0'/0/0"},
                    {"coin": "ETH", "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "kind": "ethereum", "path": "m/44'/60'/0'/0/0"},
                ]),
        Finding(kind="Private key (WIF, BTC)", coin="BTC",
                location=r"E:\old_notes.txt", confidence="high", encrypted=False,
                note="A valid Wallet-Import-Format private key (checksum OK).",
                secret="L3pr5wQW9YhGyNJJPB59ZZaniFFUzXFujeBvpeE3bUGHiJ28Fjki", secret_type="wif",
                addresses=[{"coin": "BTC", "address": "12rqARA5bAvxBZgwY75mpF7cu3bXs9gAqd", "kind": "legacy"}]),
        Finding(kind="Ethereum keystore (UTC JSON)", coin="ETH",
                location=r"E:\Ethereum\keystore\UTC--2017-06-01--0ba...416", confidence="high",
                encrypted=True, note="Encrypted Ethereum keystore - needs its password.",
                detail="Public address: 0x0BAad412cB3109f3B0cfCdC63CeE75bCA9f83416",
                addresses=[{"coin": "ETH", "address": "0x0BAad412cB3109f3B0cfCdC63CeE75bCA9f83416", "kind": "ethereum"}]),
        Finding(kind="Raw signature: wallet.dat master key record", coin="BTC",
                location=r"disk_image.img @ offset 1049576 (0x100428)", confidence="high",
                encrypted=True, note="'mkey' record means the wallet is ENCRYPTED.",
                detail="Found by raw byte scan - may be a live or DELETED wallet remnant."),
    ]


def fake_balances(app):
    # pretend the balance check ran
    app.balances_by_addr = {
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq": balance.AddressBalance("BTC", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "ok", 0.1337, 8900.0, 5),
        "12rqARA5bAvxBZgwY75mpF7cu3bXs9gAqd": balance.AddressBalance("BTC", "12rqARA5bAvxBZgwY75mpF7cu3bXs9gAqd", "ok", 0.0, 0.0, 0),
        "0x0BAad412cB3109f3B0cfCdC63CeE75bCA9f83416": balance.AddressBalance("ETH", "0x0BAad412cB3109f3B0cfCdC63CeE75bCA9f83416", "ok", 2.5, 6250.0, 12),
        "1BitcoinEaterAddressDontSendf59kuE": balance.AddressBalance("BTC", "1BitcoinEaterAddressDontSendf59kuE", "unreachable"),
    }
    app.total_usd = 15150.0


def shot(name):
    time.sleep(1.1)
    subprocess.run(["scrot", "-o", os.path.join(OUT, name)], check=False)
    print("captured", name)


def main():
    app = WalletFinderApp()
    app.geometry("1180x800")
    app.update(); app.update_idletasks()
    app.navigate("home"); app.update(); app.update_idletasks(); shot("01_home.png")
    app.navigate("scan"); app.update(); app.update_idletasks(); shot("02_scan.png")
    app.findings = sample_findings()
    fake_balances(app)
    app.navigate("results"); app.update(); app.update_idletasks()
    app._apply_known_balances()
    app._update_total_label({"by_coin": {"BTC": {"balance": 0.1337, "usd": 8900.0, "unreachable": 1},
                                         "ETH": {"balance": 2.5, "usd": 6250.0, "unreachable": 0}},
                             "total_usd": 15150.0})
    app.update(); app.update_idletasks(); shot("03_results.png")
    app.navigate("hardware"); app.update(); app.update_idletasks(); shot("04_hardware.png")
    app.navigate("help"); app.update(); app.update_idletasks(); shot("05_nextsteps.png")
    app.navigate("about"); app.update(); app.update_idletasks(); shot("06_about.png")
    # consent dialog
    app.navigate("results"); app.update()
    try:
        import threading
        t = threading.Thread(target=lambda: (time.sleep(1.4), subprocess.run(["scrot","-o",os.path.join(OUT,"07_consent.png")],check=False), app.after(1,lambda: [w.destroy() for w in app.winfo_children() if isinstance(w, __import__('customtkinter').CTkToplevel)])), daemon=True)
        t.start()
        app._ask_balance_consent()
    except Exception as e:
        print("consent shot skipped:", e)
    app.destroy()


if __name__ == "__main__":
    main()
