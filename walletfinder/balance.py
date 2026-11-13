"""Online balance checks for PUBLIC addresses only.

Privacy rules (hard):
  * Only public addresses are ever sent over the network.
  * Private keys, seeds, xprv and wallet files are NEVER transmitted.
  * Addresses are derived locally (see crypto.py) before any lookup.
Uses only the Python standard library (urllib) so the Windows build stays light.

Providers (all free, no API key):
  BTC  -> mempool.space   (fallback blockstream.info)
  LTC  -> litecoinspace.org (mempool.space-compatible)
  DOGE -> blockchair.com
  ETH  -> blockchair.com
  USD prices -> coingecko.com
On any network error we report status 'unreachable' (shown as "couldn't check"),
never a misleading zero.
"""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field

USER_AGENT = "WalletFinder/1.0 (+local recovery tool)"
TIMEOUT = 15

SATS = 100_000_000
WEI = 10 ** 18

COIN_DECIMALS = {"BTC": SATS, "LTC": SATS, "DOGE": SATS, "ETH": WEI}
COINGECKO_IDS = {"BTC": "bitcoin", "ETH": "ethereum", "LTC": "litecoin", "DOGE": "dogecoin"}


@dataclass
class AddressBalance:
    coin: str
    address: str
    status: str = "ok"          # "ok" | "unreachable" | "empty"
    balance: float = 0.0        # in whole coins
    usd: float = 0.0
    tx_count: int = 0
    kind: str = ""
    path: str = ""


def _get_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def get_prices():
    """Return {coin: usd_price}. Empty dict on failure."""
    ids = ",".join(COINGECKO_IDS.values())
    url = f"https://api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=usd"
    try:
        data = _get_json(url)
        out = {}
        for coin, cid in COINGECKO_IDS.items():
            out[coin] = float(data.get(cid, {}).get("usd", 0.0))
        return out
    except Exception:
        return {}


# ---- per-coin lookups -----------------------------------------------------

def _btc_like(address: str, base: str):
    """mempool.space-style /api/address/{a} -> chain_stats sums (sats)."""
    data = _get_json(f"{base}/api/address/{address}")
    cs = data.get("chain_stats", {})
    ms = data.get("mempool_stats", {})
    funded = cs.get("funded_txo_sum", 0) + ms.get("funded_txo_sum", 0)
    spent = cs.get("spent_txo_sum", 0) + ms.get("spent_txo_sum", 0)
    txs = cs.get("tx_count", 0) + ms.get("tx_count", 0)
    return funded - spent, txs


def _blockchair(chain: str, address: str, decimals: int):
    data = _get_json(f"https://api.blockchair.com/{chain}/dashboards/address/{address}")
    rec = data.get("data", {}).get(address, {})
    addr = rec.get("address", {})
    bal = addr.get("balance", 0) or 0
    txs = addr.get("transaction_count", 0) or 0
    return int(bal), txs


def check_address(coin: str, address: str) -> AddressBalance:
    """Look up a single public address. Returns AddressBalance (status ok/unreachable)."""
    try:
        if coin == "BTC":
            try:
                raw, txs = _btc_like(address, "https://mempool.space")
            except Exception:
                raw, txs = _btc_like(address, "https://blockstream.info")
            bal = raw / SATS
        elif coin == "LTC":
            raw, txs = _btc_like(address, "https://litecoinspace.org")
            bal = raw / SATS
        elif coin == "DOGE":
            raw, txs = _blockchair("dogecoin", address, SATS)
            bal = raw / SATS
        elif coin == "ETH":
            raw, txs = _blockchair("ethereum", address, WEI)
            bal = raw / WEI
        else:
            return AddressBalance(coin, address, status="unreachable")
        return AddressBalance(coin, address, status="ok", balance=bal, tx_count=txs)
    except Exception:
        return AddressBalance(coin, address, status="unreachable")


def check_addresses(addr_list, prices=None, progress=None, stop=None, gap_limit=20, delay=0.15):
    """Check many addresses. addr_list: list of dicts {coin,address,kind,path}.

    Groups by (coin, path-prefix) and applies a gap limit: after `gap_limit`
    consecutive addresses with no transactions it stops scanning that branch
    (standard BIP44 behaviour), to avoid hammering the APIs.
    Returns (results, totals) where totals = {coin: {"balance":x,"usd":y}}.
    """
    if prices is None:
        prices = get_prices()
    results = []
    # group by coin + path purpose so gap limit applies per branch
    from collections import defaultdict
    groups = defaultdict(list)
    for a in addr_list:
        purpose = (a.get("path") or "").split("/")[1] if a.get("path") else a.get("kind", "")
        groups[(a["coin"], purpose)].append(a)

    done = 0
    total_n = len(addr_list)
    for key, items in groups.items():
        empties = 0
        for a in items:
            if stop and stop():
                break
            r = check_address(a["coin"], a["address"])
            r.kind = a.get("kind", "")
            r.path = a.get("path", "")
            if r.status == "ok":
                price = prices.get(a["coin"], 0.0)
                r.usd = r.balance * price
                if r.balance == 0 and r.tx_count == 0:
                    r.status = "empty"
                    empties += 1
                else:
                    empties = 0
            results.append(r)
            done += 1
            if progress:
                progress(done, total_n, r)
            if delay:
                time.sleep(delay)
            if empties >= gap_limit:
                break
    totals = _totals(results)
    return results, totals


def _totals(results):
    from collections import defaultdict
    t = defaultdict(lambda: {"balance": 0.0, "usd": 0.0, "unreachable": 0})
    for r in results:
        if r.status == "ok":
            t[r.coin]["balance"] += r.balance
            t[r.coin]["usd"] += r.usd
        elif r.status == "unreachable":
            t[r.coin]["unreachable"] += 1
    grand_usd = sum(v["usd"] for v in t.values())
    return {"by_coin": dict(t), "total_usd": grand_usd}
