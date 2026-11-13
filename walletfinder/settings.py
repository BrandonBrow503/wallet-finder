"""Tiny local settings store (remembers the balance-check choice, etc.)."""
import json
import os


def _config_dir():
    if os.name == "nt":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    elif os.sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    d = os.path.join(base, "WalletFinder")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        d = os.path.expanduser("~")
    return d


_PATH = os.path.join(_config_dir(), "settings.json")


def load():
    try:
        with open(_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save(data):
    try:
        with open(_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass
