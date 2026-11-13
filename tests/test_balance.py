"""Balance module tests - logic only, network calls are stubbed (no real calls)."""
from walletfinder import balance


def test_check_addresses_stubbed(monkeypatch):
    def fake_check(coin, address):
        # pretend first BTC address has 0.5 BTC, others empty
        if address == "1rich":
            return balance.AddressBalance(coin, address, status="ok", balance=0.5, tx_count=3)
        return balance.AddressBalance(coin, address, status="ok", balance=0.0, tx_count=0)

    monkeypatch.setattr(balance, "check_address", fake_check)
    addrs = [
        {"coin": "BTC", "address": "1rich", "kind": "legacy", "path": "m/44'/0'/0'/0/0"},
        {"coin": "BTC", "address": "1poor", "kind": "legacy", "path": "m/44'/0'/0'/0/1"},
    ]
    results, totals = balance.check_addresses(addrs, prices={"BTC": 60000.0}, delay=0)
    rich = [r for r in results if r.address == "1rich"][0]
    assert rich.usd == 30000.0
    assert totals["total_usd"] == 30000.0
    assert totals["by_coin"]["BTC"]["balance"] == 0.5


def test_unreachable_reported(monkeypatch):
    monkeypatch.setattr(balance, "check_address",
                        lambda c, a: balance.AddressBalance(c, a, status="unreachable"))
    addrs = [{"coin": "ETH", "address": "0xabc", "kind": "ethereum", "path": "m/44'/60'/0'/0/0"}]
    results, totals = balance.check_addresses(addrs, prices={"ETH": 3000.0}, delay=0)
    assert results[0].status == "unreachable"
    assert totals["by_coin"]["ETH"]["unreachable"] == 1


def test_gap_limit(monkeypatch):
    calls = []

    def fake(coin, address):
        calls.append(address)
        return balance.AddressBalance(coin, address, status="ok", balance=0.0, tx_count=0)
    monkeypatch.setattr(balance, "check_address", fake)
    addrs = [{"coin": "BTC", "address": f"a{i}", "kind": "legacy", "path": f"m/44'/0'/0'/0/{i}"}
             for i in range(50)]
    balance.check_addresses(addrs, prices={"BTC": 1.0}, delay=0, gap_limit=5)
    # should stop after 5 consecutive empties, not check all 50
    assert len(calls) <= 6
