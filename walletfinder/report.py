"""Local report export and 'copy wallet file to a safe folder' backup.

All output is written LOCALLY only (chosen by the user). Nothing is uploaded.
"""
from __future__ import annotations

import json
import os
import shutil
import datetime
import html


def _mask(secret: str) -> str:
    if not secret:
        return ""
    s = secret
    if len(s) <= 10:
        return s[:2] + "…"
    return s[:4] + "…" + s[-4:]


def export_json(findings, path, include_secrets=False):
    data = []
    for f in findings:
        d = f.to_dict()
        if not include_secrets:
            d["secret"] = _mask(d.get("secret", ""))
        data.append(d)
    payload = {
        "tool": "Wallet Finder",
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "include_secrets": include_secrets,
        "count": len(findings),
        "findings": data,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def export_text(findings, path, include_secrets=False):
    lines = []
    lines.append("WALLET FINDER - RECOVERY REPORT")
    lines.append("Recover crypto from your own old drives.")
    lines.append("Generated: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    lines.append("=" * 60)
    lines.append("")
    lines.append("IMPORTANT: Coins on a drive that belongs to someone else are")
    lines.append("still theirs. Return them; do not take them.")
    lines.append("")
    lines.append(f"Total items found: {len(findings)}")
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append(f"[{i}] {f.kind}")
        lines.append(f"    Coin:       {f.coin}")
        lines.append(f"    Location:   {f.location}")
        lines.append(f"    Confidence: {f.confidence}")
        if f.encrypted is True:
            lines.append("    Encrypted:  YES - needs the wallet password")
        elif f.encrypted is False:
            lines.append("    Encrypted:  no master-key record seen")
        if f.note:
            lines.append(f"    Note:       {f.note}")
        if f.detail:
            lines.append(f"    Detail:     {f.detail}")
        if f.secret:
            shown = f.secret if include_secrets else _mask(f.secret)
            lines.append(f"    Secret ({f.secret_type}): {shown}")
        for a in f.addresses[:6]:
            lines.append(f"    Address:    [{a.get('coin','?')}/{a.get('kind','')}] {a.get('address','')}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def export_html(findings, path, include_secrets=False, balances_total=None):
    rows = []
    for i, f in enumerate(findings, 1):
        enc = "needs password" if f.encrypted is True else ("" if f.encrypted is None else "unencrypted?")
        secret = ""
        if f.secret:
            secret = html.escape(f.secret if include_secrets else _mask(f.secret))
        addrs = "<br>".join(html.escape(f"{a.get('coin','')}/{a.get('kind','')}: {a.get('address','')}")
                            for a in f.addresses[:6])
        rows.append(f"""<tr>
<td>{i}</td><td>{html.escape(f.kind)}</td><td>{html.escape(f.coin)}</td>
<td class='loc'>{html.escape(f.location)}</td>
<td><span class='conf {f.confidence}'>{f.confidence}</span></td>
<td>{enc}</td><td class='mono'>{secret}</td><td class='mono small'>{addrs}</td></tr>""")
    total_html = ""
    if balances_total:
        total_html = f"<p class='total'>Estimated total value found: <b>${balances_total:,.2f}</b></p>"
    doc = f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>Wallet Finder report</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f1419;color:#e7e9ea;margin:0;padding:24px;font-size:17px}}
h1{{font-size:26px}} .sub{{color:#8b98a5}}
.notice{{background:#1d2730;border-left:4px solid #f6c344;padding:14px 18px;border-radius:8px;margin:18px 0}}
table{{border-collapse:collapse;width:100%;margin-top:16px}}
th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #26323c;vertical-align:top}}
th{{color:#8b98a5;font-weight:600}}
.mono{{font-family:ui-monospace,Menlo,Consolas,monospace}} .small{{font-size:13px}}
.loc{{word-break:break-all;max-width:320px;font-size:13px;color:#b9c2cb}}
.conf{{padding:2px 10px;border-radius:999px;font-size:13px}}
.conf.high{{background:#113d2b;color:#4ee39a}} .conf.medium{{background:#3d3411;color:#f6c344}} .conf.low{{background:#3a2a2a;color:#e78}}
.total{{font-size:20px;background:#113d2b;display:inline-block;padding:10px 18px;border-radius:10px}}
</style></head><body>
<h1>Wallet Finder — recovery report</h1>
<p class=sub>Recover crypto from your own old drives. Generated {datetime.datetime.now():%Y-%m-%d %H:%M}.</p>
<div class=notice><b>Please note:</b> coins on a drive that belongs to someone else are still theirs. Return them; do not take them.</div>
{total_html}
<p>Total items found: <b>{len(findings)}</b></p>
<table><tr><th>#</th><th>Type</th><th>Coin</th><th>Location</th><th>Confidence</th><th>Encrypted</th><th>Secret</th><th>Addresses</th></tr>
{''.join(rows)}
</table>
<p class=sub style='margin-top:30px'>Secrets are masked unless you exported with reveal on. Import finds into the official wallet software yourself — this tool never moves funds.</p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def copy_to_safe_folder(src: str, dest_dir: str) -> str:
    """Copy a found wallet file to a user-chosen safe folder (read src, write dest)."""
    os.makedirs(dest_dir, exist_ok=True)
    base = os.path.basename(src.split(" @ ")[0].split(" (raw")[0])
    dest = os.path.join(dest_dir, base)
    n = 1
    while os.path.exists(dest):
        root, ext = os.path.splitext(base)
        dest = os.path.join(dest_dir, f"{root}_{n}{ext}")
        n += 1
    shutil.copy2(src, dest)
    return dest
