# Wallet Finder — *Recover crypto from your own old drives*

A simple desktop app that scans your old hard drives, USB sticks and memory
cards for forgotten cryptocurrency wallets and keys, so you can recover **your
own** coins.

> **Only for drives you own.** This is for recovering *your* coins from *your*
> old drives (and your family's, with their OK). If coins turn up on a drive
> that belongs to someone else, they are still that person's property —
> **return them, don't take them.**

It is **read-only** (it never changes the drive it scans) and it can **never
send or move coins**. You do the final recovery step yourself in the official
wallet software.

---

## For Brandon — how to run it (Windows)

1. Download **`WalletFinder.exe`** from the [latest release](https://github.com/BrandonBrow503/wallet-finder/releases/latest) onto your Windows PC.
2. Double-click it. If Windows shows a blue "Windows protected your PC" box,
   click **More info → Run anyway** (this happens with any new app that isn't
   code-signed).
3. Plug in an old drive. Not sure how? Open **"Connecting drives"** in the app
   for a plain, step-by-step guide (adapters, laptop drives, SD cards, floppies).
4. Click **"Scan a drive"**, choose the old drive, and press **Start file scan**.
5. Look at **Results**. Press **💰 Check balances** to see how much each wallet
   holds (you'll be asked once — only *public* addresses ever go online).
6. To actually recover coins, follow **"Next steps"** in the app — it tells you
   which official wallet to import each find into.

**Tip:** to find *deleted* wallets too, use the **deep (raw) scan**. For a raw
drive that needs it, right-click the app and choose **Run as administrator**.
Scanning a saved **disk image** does not need admin.

**If a drive clicks or buzzes — stop using it.** See the in-app guide; it may
be failing and need a professional.

---

## What's in this folder

| File | What it is |
|------|------------|
| [Releases](https://github.com/BrandonBrow503/wallet-finder/releases/latest) | **`WalletFinder.exe`** — Windows app (64-bit), built by GitHub Actions. |
| `main.py` + `walletfinder/` | Plain Python source (the fallback — runs anywhere with Python 3). |
| `tests/` | Automated tests + a generator for safe, fake test data (fixtures are generated on the fly). |
| `previews/` | Screenshots of each screen. |
| `build_windows.sh` / `build_linux.sh` | How the apps were built. |

## Run from source (fallback, any OS)

```bash
pip install customtkinter          # the only runtime dependency
python3 main.py
```
(On Linux you may also need the system package `python3-tk`.)

## What it looks for

- **Bitcoin Core / Bitcoin-Qt `wallet.dat`** (Berkeley DB, incl. 2009–2013 era)
- **Litecoin / Dogecoin / other Core-fork `wallet.dat`**
- **Electrum** wallets (`default_wallet`), **MultiBit** (`.wallet`/`.key`),
  **Armory** (`.wallet`), **Blockchain.info** backups (`wallet.aes.json`),
  **Exodus**/**Jaxx** data
- **Ethereum / Geth / MyEtherWallet** keystores (`UTC--…` JSON)
- **Paper-wallet** images / PDFs
- Loose **WIF private keys** (checksum-validated), **xprv** extended keys,
  **BIP39 seed phrases** (wordlist + checksum validated), and (low-confidence)
  raw 64-hex keys
- Known default wallet folders for Windows XP/7/10/11, macOS and Linux
- **Deleted-wallet remnants** via a raw byte-signature scan of a disk image
  (Berkeley DB magic, `mkey`/`ckey`/`key`/`name` records, keystore JSON, WIF)

## Your privacy

- Scanning is **read-only**. Opening-handles are read-only; nothing is written
  to the scanned drive.
- Balance checks send **only public addresses** to public explorers
  (mempool.space, litecoinspace.org, blockchair.com) and prices from
  coingecko.com. **Private keys, seeds and wallet files are never transmitted.**
- Addresses are derived **locally** from any keys/seeds found.
- There is **no sweep/send feature** by design. If a wallet is encrypted you
  need its original password — there is **no cracking feature**.
