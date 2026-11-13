"""Wallet Finder - modern GUI (customtkinter).

Large readable text, clean layout, works on Windows/macOS/Linux.
All heavy work (scanning, balance lookups) runs on background threads so the
window never freezes. Nothing here can send or move coins.
"""
from __future__ import annotations

import os
import queue
import threading
import webbrowser

import customtkinter as ctk
from tkinter import filedialog, messagebox

from .. import __version__, scanner, balance, report, content, settings

# ---- theme ---------------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG = "#0f1419"
CARD = "#182028"
CARD2 = "#1f2a33"
ACCENT = "#2f8fff"
GOOD = "#2ec77a"
WARN = "#f6c344"
MUTED = "#8b98a5"
TEXT = "#e7e9ea"

CONF_COLOR = {"high": GOOD, "medium": WARN, "low": "#e78"}
COIN_SYMBOL = {"BTC": "₿", "ETH": "Ξ", "LTC": "Ł", "DOGE": "Ð"}


def F(size, weight="normal"):
    return ctk.CTkFont(family="Segoe UI", size=size, weight=weight)


class WalletFinderApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Wallet Finder — " + content.TAGLINE)
        self.geometry("1120x760")
        self.minsize(900, 640)
        self.configure(fg_color=BG)

        self.findings = []
        self.settings = settings.load()
        self.balance_enabled = None       # None = not asked this session
        self.prices = {}
        self.balances_by_addr = {}        # address -> AddressBalance
        self.total_usd = 0.0
        self.scan_thread = None
        self.stop_flag = False
        self._ui_queue = queue.Queue()
        self._row_widgets = {}

        self._build_sidebar()
        self._build_main()
        self.show_home()
        self.after(100, self._drain_queue)

    # ------------------------------------------------------------------ UI
    def _build_sidebar(self):
        bar = ctk.CTkFrame(self, width=230, fg_color=CARD, corner_radius=0)
        bar.pack(side="left", fill="y")
        bar.pack_propagate(False)

        ctk.CTkLabel(bar, text="🔑  Wallet Finder", font=F(22, "bold"),
                     text_color=TEXT).pack(padx=22, pady=(26, 2), anchor="w")
        ctk.CTkLabel(bar, text=content.TAGLINE, font=F(13), text_color=MUTED,
                     wraplength=190, justify="left").pack(padx=22, pady=(0, 24), anchor="w")

        self.nav_buttons = {}
        for key, label, icon in [
            ("home", "Home", "🏠"),
            ("scan", "Scan a drive", "🔍"),
            ("results", "Results", "📋"),
            ("hardware", "Connecting drives", "🔌"),
            ("help", "Next steps", "💡"),
            ("about", "About & safety", "🛡️"),
        ]:
            b = ctk.CTkButton(bar, text=f"  {icon}   {label}", font=F(16),
                              anchor="w", height=46, corner_radius=10,
                              fg_color="transparent", hover_color=CARD2,
                              text_color=TEXT,
                              command=lambda k=key: self.navigate(k))
            b.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[key] = b

        ctk.CTkLabel(bar, text=f"v{__version__} · read-only · never moves funds",
                     font=F(11), text_color=MUTED, wraplength=200,
                     justify="left").pack(side="bottom", padx=20, pady=16, anchor="w")

    def _build_main(self):
        self.main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.main.pack(side="left", fill="both", expand=True)
        self.frames = {}

    def navigate(self, key):
        for k, b in self.nav_buttons.items():
            b.configure(fg_color=ACCENT if k == key else "transparent")
        {"home": self.show_home, "scan": self.show_scan, "results": self.show_results,
         "hardware": self.show_hardware, "help": self.show_help,
         "about": self.show_about}[key]()

    def _clear_main(self):
        for w in self.main.winfo_children():
            w.destroy()

    def _scroll(self):
        f = ctk.CTkScrollableFrame(self.main, fg_color=BG)
        f.pack(fill="both", expand=True, padx=28, pady=22)
        return f

    def _card(self, parent, color=CARD):
        c = ctk.CTkFrame(parent, fg_color=color, corner_radius=14)
        c.pack(fill="x", pady=10)
        return c

    def _notice(self, parent, title, body, color=WARN):
        c = ctk.CTkFrame(parent, fg_color=CARD2, corner_radius=12)
        c.pack(fill="x", pady=10)
        strip = ctk.CTkFrame(c, fg_color=color, width=6, corner_radius=12)
        strip.pack(side="left", fill="y", padx=(0, 0))
        inner = ctk.CTkFrame(c, fg_color="transparent")
        inner.pack(side="left", fill="both", expand=True, padx=16, pady=14)
        ctk.CTkLabel(inner, text=title, font=F(16, "bold"), text_color=TEXT,
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(inner, text=body, font=F(14), text_color=TEXT, justify="left",
                     wraplength=760, anchor="w").pack(fill="x", pady=(4, 0))
        return c

    # ----------------------------------------------------------------- HOME
    def show_home(self):
        self._clear_main()
        s = self._scroll()
        ctk.CTkLabel(s, text="Recover crypto from your own old drives",
                     font=F(30, "bold"), text_color=TEXT, justify="left",
                     wraplength=820, anchor="w").pack(fill="x", pady=(4, 2))
        ctk.CTkLabel(s, text="Dig through old hard drives, USB sticks and memory cards for "
                             "forgotten Bitcoin and other crypto wallets — safely and read-only.",
                     font=F(16), text_color=MUTED, justify="left", wraplength=820,
                     anchor="w").pack(fill="x", pady=(0, 14))

        self._notice(s, "Only for drives you own", content.OWNERSHIP_NOTICE, WARN)
        self._notice(s, "Your keys stay on this computer", content.PRIVACY_NOTICE, ACCENT)

        c = self._card(s)
        ctk.CTkLabel(c, text="How it works", font=F(19, "bold"), text_color=TEXT,
                     anchor="w").pack(fill="x", padx=20, pady=(16, 4))
        for n, t in [
            ("1.", "Connect an old drive. Not sure how? See “Connecting drives”."),
            ("2.", "Scan it. We read the drive without ever changing it."),
            ("3.", "Review what we found — wallet files, keys and seed phrases."),
            ("4.", "Optionally check balances online (public addresses only)."),
            ("5.", "Import your finds into the official wallet yourself to recover coins."),
        ]:
            row = ctk.CTkFrame(c, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=3)
            ctk.CTkLabel(row, text=n, font=F(16, "bold"), text_color=ACCENT,
                         width=28, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=t, font=F(15), text_color=TEXT, justify="left",
                         wraplength=720, anchor="w").pack(side="left")
        ctk.CTkLabel(c, text="", font=F(6)).pack()

        ctk.CTkButton(s, text="🔍  Scan a drive now", font=F(18, "bold"), height=56,
                      corner_radius=12, fg_color=ACCENT, hover_color="#1f6fd6",
                      command=lambda: self.navigate("scan")).pack(fill="x", pady=(14, 6))

    # ----------------------------------------------------------------- SCAN
    def show_scan(self):
        self._clear_main()
        s = self._scroll()
        ctk.CTkLabel(s, text="Scan a drive", font=F(28, "bold"), text_color=TEXT,
                     anchor="w").pack(fill="x", pady=(2, 10))

        # file-level scan card
        c = self._card(s)
        ctk.CTkLabel(c, text="1 · Scan files on a drive or folder", font=F(19, "bold"),
                     text_color=TEXT, anchor="w").pack(fill="x", padx=20, pady=(16, 2))
        ctk.CTkLabel(c, text="Pick a whole drive (e.g. the old drive you plugged in) or any "
                             "folder. Works with FAT16/FAT32/exFAT/NTFS and, where your "
                             "computer can read them, Mac (HFS+) and Linux (ext) drives.",
                     font=F(14), text_color=MUTED, justify="left", wraplength=740,
                     anchor="w").pack(fill="x", padx=20)
        self.folder_var = ctk.StringVar(value="")
        row = ctk.CTkFrame(c, fg_color="transparent"); row.pack(fill="x", padx=20, pady=10)
        self.folder_entry = ctk.CTkEntry(row, textvariable=self.folder_var, font=F(14),
                                         height=42, placeholder_text="No folder chosen yet")
        self.folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row, text="Choose folder…", font=F(14), height=42, width=150,
                      command=self._pick_folder).pack(side="left")
        ctk.CTkButton(c, text="▶  Start file scan", font=F(16, "bold"), height=48,
                      fg_color=GOOD, hover_color="#24a862", corner_radius=10,
                      command=self._start_file_scan).pack(fill="x", padx=20, pady=(4, 18))

        # raw/image scan card
        c2 = self._card(s, CARD2)
        ctk.CTkLabel(c2, text="2 · Deep scan a disk image (finds deleted wallets)",
                     font=F(19, "bold"), text_color=TEXT, anchor="w").pack(fill="x", padx=20, pady=(16, 2))
        ctk.CTkLabel(c2, text="This looks at the raw bytes of a drive image, so it can find "
                             "pieces of DELETED wallets too. Best practice: make a one-time "
                             "image (.img/.dd) of an old or shaky drive first, then scan the "
                             "image here.\n\nScanning a raw drive directly needs Administrator "
                             "rights: on Windows, right-click the app and choose “Run as "
                             "administrator”. Scanning an image file does not.",
                     font=F(14), text_color=MUTED, justify="left", wraplength=740,
                     anchor="w").pack(fill="x", padx=20)
        self.image_var = ctk.StringVar(value="")
        row2 = ctk.CTkFrame(c2, fg_color="transparent"); row2.pack(fill="x", padx=20, pady=10)
        self.image_entry = ctk.CTkEntry(row2, textvariable=self.image_var, font=F(14),
                                        height=42, placeholder_text="No image/device chosen")
        self.image_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row2, text="Choose image…", font=F(14), height=42, width=150,
                      command=self._pick_image).pack(side="left")
        ctk.CTkButton(c2, text="▶  Start deep (raw) scan", font=F(16, "bold"), height=48,
                      fg_color="#8a5cf6", hover_color="#6f40e0", corner_radius=10,
                      command=self._start_raw_scan).pack(fill="x", padx=20, pady=(4, 18))

        # progress area
        self.progress_card = self._card(s)
        self.progress_label = ctk.CTkLabel(self.progress_card, text="Ready.", font=F(15),
                                            text_color=TEXT, anchor="w", justify="left",
                                            wraplength=760)
        self.progress_label.pack(fill="x", padx=20, pady=(16, 6))
        self.progress_bar = ctk.CTkProgressBar(self.progress_card, height=14)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=20, pady=(0, 8))
        self.stop_btn = ctk.CTkButton(self.progress_card, text="Stop", font=F(14),
                                      fg_color="#b23b3b", hover_color="#8f2e2e", width=100,
                                      command=self._stop_scan, state="disabled")
        self.stop_btn.pack(anchor="e", padx=20, pady=(0, 16))

    def _pick_folder(self):
        d = filedialog.askdirectory(title="Choose a drive or folder to scan")
        if d:
            self.folder_var.set(d)

    def _pick_image(self):
        f = filedialog.askopenfilename(title="Choose a disk image or device",
                                       filetypes=[("Disk images", "*.img *.dd *.raw *.bin *.iso"),
                                                  ("All files", "*.*")])
        if f:
            self.image_var.set(f)

    # --------------------------------------------------- scan control/threads
    def _start_file_scan(self):
        path = self.folder_var.get().strip()
        if not path or not os.path.isdir(path):
            messagebox.showwarning("Choose a folder", "Please choose a drive or folder to scan first.")
            return
        self._run_scan(lambda: scanner.scan_folder(path, progress=self._scan_progress,
                                                    stop=lambda: self.stop_flag),
                       f"Scanning files in {path} …")

    def _start_raw_scan(self):
        path = self.image_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Choose an image", "Please choose a disk image or device first.")
            return
        self._run_scan(lambda: scanner.scan_raw_image(path, progress=self._raw_progress,
                                                       stop=lambda: self.stop_flag),
                       f"Deep-scanning {path} …")

    def _run_scan(self, fn, label):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Busy", "A scan is already running.")
            return
        self.stop_flag = False
        self.progress_bar.set(0)
        self.progress_label.configure(text=label)
        self.stop_btn.configure(state="normal")

        def worker():
            try:
                results = fn()
                self._ui_queue.put(("scan_done", results))
            except Exception as e:
                self._ui_queue.put(("scan_error", str(e)))

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        self.stop_flag = True
        self.progress_label.configure(text="Stopping…")

    def _scan_progress(self, path, scanned, found):
        self._ui_queue.put(("progress", (f"Scanned {scanned} files · {found} finds so far…",
                                          None)))

    def _raw_progress(self, path, pos, found, total):
        frac = (pos / total) if total else 0
        mb = pos / (1024 * 1024)
        tot = total / (1024 * 1024)
        self._ui_queue.put(("progress", (f"Deep scan: {mb:.0f} / {tot:.0f} MB · {found} finds…",
                                          frac)))

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self._ui_queue.get_nowait()
                if kind == "progress":
                    text, frac = payload
                    if hasattr(self, "progress_label") and self.progress_label.winfo_exists():
                        self.progress_label.configure(text=text)
                        if frac is not None:
                            self.progress_bar.set(frac)
                elif kind == "scan_done":
                    self._on_scan_done(payload)
                elif kind == "scan_error":
                    if hasattr(self, "progress_label") and self.progress_label.winfo_exists():
                        self.progress_label.configure(text="Error: " + payload)
                    self.stop_btn.configure(state="disabled")
                    messagebox.showerror("Scan error", payload)
                elif kind == "bal_progress":
                    self._on_bal_progress(payload)
                elif kind == "bal_done":
                    self._on_bal_done(payload)
        except queue.Empty:
            pass
        self.after(120, self._drain_queue)

    def _on_scan_done(self, results):
        # merge (avoid duplicates by (kind, location, secret))
        existing = {(f.kind, f.location, f.secret) for f in self.findings}
        for f in results:
            if (f.kind, f.location, f.secret) not in existing:
                self.findings.append(f)
        if hasattr(self, "progress_label") and self.progress_label.winfo_exists():
            self.progress_bar.set(1)
            self.progress_label.configure(
                text=f"Done. {len(results)} items in this scan · {len(self.findings)} total. "
                     f"See the Results tab.")
            self.stop_btn.configure(state="disabled")
        self.navigate("results")

    # -------------------------------------------------------------- RESULTS
    def show_results(self):
        self._clear_main()
        top = ctk.CTkFrame(self.main, fg_color=BG)
        top.pack(fill="x", padx=28, pady=(22, 0))
        ctk.CTkLabel(top, text="Results", font=F(28, "bold"), text_color=TEXT,
                     anchor="w").pack(side="left")

        # toolbar
        tb = ctk.CTkFrame(self.main, fg_color=BG)
        tb.pack(fill="x", padx=28, pady=(8, 0))
        self.check_bal_btn = ctk.CTkButton(tb, text="💰  Check balances", font=F(15, "bold"),
                                           height=44, fg_color=GOOD, hover_color="#24a862",
                                           command=self._on_check_balances)
        self.check_bal_btn.pack(side="left", padx=(0, 8))
        ctk.CTkButton(tb, text="⬇  Export report", font=F(15), height=44,
                      command=self._export_report).pack(side="left", padx=8)
        ctk.CTkButton(tb, text="🗑  Clear", font=F(15), height=44, fg_color=CARD2,
                      hover_color="#2a3742", command=self._clear_results).pack(side="left", padx=8)

        self.total_label = ctk.CTkLabel(tb, text="", font=F(17, "bold"), text_color=GOOD)
        self.total_label.pack(side="right")
        self._update_total_label()

        self.results_scroll = ctk.CTkScrollableFrame(self.main, fg_color=BG)
        self.results_scroll.pack(fill="both", expand=True, padx=28, pady=16)
        self._row_widgets = {}

        if not self.findings:
            ctk.CTkLabel(self.results_scroll,
                         text="Nothing yet. Go to “Scan a drive” to search an old drive.",
                         font=F(16), text_color=MUTED).pack(pady=40)
            return

        for i, f in enumerate(self.findings):
            self._render_finding(i, f)

    def _render_finding(self, idx, f):
        card = ctk.CTkFrame(self.results_scroll, fg_color=CARD, corner_radius=12)
        card.pack(fill="x", pady=7)
        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=18, pady=(14, 2))
        sym = COIN_SYMBOL.get(f.coin, "•")
        ctk.CTkLabel(head, text=f"{sym}  {f.kind}", font=F(18, "bold"), text_color=TEXT,
                     anchor="w").pack(side="left")
        conf = ctk.CTkLabel(head, text=f.confidence.upper(), font=F(12, "bold"),
                            fg_color=CONF_COLOR.get(f.confidence, MUTED),
                            text_color="#06110a", corner_radius=8, width=74, height=24)
        conf.pack(side="right")
        if f.encrypted is True:
            ctk.CTkLabel(head, text="🔒 needs password", font=F(12, "bold"),
                         fg_color=WARN, text_color="#2a1f00", corner_radius=8,
                         height=24).pack(side="right", padx=8)

        ctk.CTkLabel(card, text="📁 " + f.location, font=F(13), text_color=MUTED,
                     anchor="w", justify="left", wraplength=720).pack(fill="x", padx=18, pady=(2, 0))
        if f.note:
            ctk.CTkLabel(card, text=f.note, font=F(13), text_color=TEXT, anchor="w",
                         justify="left", wraplength=720).pack(fill="x", padx=18, pady=(2, 0))
        if f.detail:
            ctk.CTkLabel(card, text=f.detail, font=F(13), text_color=WARN, anchor="w",
                         justify="left", wraplength=720).pack(fill="x", padx=18, pady=(2, 0))

        # secret (masked by default + reveal)
        if f.secret:
            srow = ctk.CTkFrame(card, fg_color=CARD2, corner_radius=8)
            srow.pack(fill="x", padx=18, pady=(8, 2))
            lbl = ctk.CTkLabel(srow, text=f"{f.secret_type.upper()}: {report._mask(f.secret)}",
                               font=ctk.CTkFont(family="Consolas", size=14), text_color=TEXT,
                               anchor="w", justify="left", wraplength=560)
            lbl.pack(side="left", fill="x", expand=True, padx=12, pady=8)
            state = {"shown": False}

            def toggle(l=lbl, st=state, sec=f.secret, t=f.secret_type):
                st["shown"] = not st["shown"]
                l.configure(text=f"{t.upper()}: " + (sec if st["shown"] else report._mask(sec)))
            ctk.CTkButton(srow, text="👁 Reveal", font=F(13), width=90,
                          command=toggle).pack(side="right", padx=10)

        # addresses + balances
        if f.addresses:
            abox = ctk.CTkFrame(card, fg_color="transparent")
            abox.pack(fill="x", padx=18, pady=(4, 2))
            shown = f.addresses[:8]
            for a in shown:
                arow = ctk.CTkFrame(abox, fg_color="transparent")
                arow.pack(fill="x", pady=1)
                tag = f"[{a.get('coin','')}/{a.get('kind','')}]"
                ctk.CTkLabel(arow, text=tag, font=F(12), text_color=ACCENT, width=150,
                             anchor="w").pack(side="left")
                ctk.CTkLabel(arow, text=a.get("address", ""),
                             font=ctk.CTkFont(family="Consolas", size=12), text_color=TEXT,
                             anchor="w").pack(side="left", padx=(4, 8))
                balw = ctk.CTkLabel(arow, text="", font=F(12, "bold"), text_color=GOOD, anchor="e")
                balw.pack(side="right")
                self._row_widgets[a.get("address", "")] = balw
            if len(f.addresses) > 8:
                ctk.CTkLabel(abox, text=f"… and {len(f.addresses)-8} more derived addresses",
                             font=F(11), text_color=MUTED, anchor="w").pack(fill="x")

        # copy-to-safe-folder for real files
        loc = f.location
        if os.path.isfile(loc.split(" @ ")[0].split(" (raw")[0]) and f.secret_type == "":
            ctk.CTkButton(card, text="📦 Copy this wallet file to a safe folder", font=F(13),
                          fg_color=CARD2, hover_color="#2a3742", height=36,
                          command=lambda p=loc: self._copy_safe(p)).pack(anchor="w", padx=18, pady=(6, 12))
        else:
            ctk.CTkLabel(card, text="", font=F(4)).pack()
        self._apply_known_balances()

    # ------------------------------------------------- balance feature
    def _collect_addresses(self):
        seen = set()
        out = []
        for f in self.findings:
            for a in f.addresses:
                key = (a.get("coin"), a.get("address"))
                if a.get("address") and key not in seen and a.get("coin") in ("BTC", "ETH", "LTC", "DOGE"):
                    seen.add(key)
                    out.append(a)
        return out

    def _on_check_balances(self):
        if not self.findings:
            messagebox.showinfo("Nothing to check", "Scan a drive first.")
            return
        if self.balance_enabled is None:
            if self.settings.get("balance_consent") is True:
                self.balance_enabled = True
            else:
                if not self._ask_balance_consent():
                    return
                self.balance_enabled = True
        addrs = self._collect_addresses()
        if not addrs:
            messagebox.showinfo("No addresses", "No public addresses were derived to check.")
            return
        self.check_bal_btn.configure(state="disabled", text="Checking…")
        self.total_label.configure(text="Checking balances…")

        def worker():
            try:
                prices = balance.get_prices()
                self.prices = prices

                def prog(done, total, r):
                    self._ui_queue.put(("bal_progress", (done, total, r)))
                results, totals = balance.check_addresses(addrs, prices=prices, progress=prog,
                                                          stop=lambda: False)
                self._ui_queue.put(("bal_done", (results, totals)))
            except Exception as e:
                self._ui_queue.put(("bal_done", ([], {"by_coin": {}, "total_usd": 0.0, "error": str(e)})))

        threading.Thread(target=worker, daemon=True).start()

    def _ask_balance_consent(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Check balances online?")
        dlg.geometry("560x420")
        dlg.configure(fg_color=BG)
        dlg.transient(self)
        dlg.grab_set()
        ctk.CTkLabel(dlg, text="💰 Check balances online?", font=F(22, "bold"),
                     text_color=TEXT).pack(pady=(24, 8), padx=24, anchor="w")
        ctk.CTkLabel(dlg, text=content.BALANCE_CONSENT, font=F(15), text_color=TEXT,
                     justify="left", wraplength=500).pack(padx=24, pady=(0, 12), anchor="w")
        remember = ctk.CTkCheckBox(dlg, text="Remember my choice", font=F(14))
        remember.pack(padx=24, anchor="w", pady=(0, 14))
        result = {"ok": False}

        def yes():
            result["ok"] = True
            if remember.get():
                self.settings["balance_consent"] = True
                settings.save(self.settings)
            dlg.destroy()

        def no():
            dlg.destroy()
        btns = ctk.CTkFrame(dlg, fg_color="transparent")
        btns.pack(fill="x", padx=24, pady=10)
        ctk.CTkButton(btns, text="Yes, check public addresses", font=F(15, "bold"), height=46,
                      fg_color=GOOD, hover_color="#24a862", command=yes).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(btns, text="No", font=F(15), height=46, width=100, fg_color=CARD2,
                      hover_color="#2a3742", command=no).pack(side="left")
        self.wait_window(dlg)
        return result["ok"]

    def _on_bal_progress(self, payload):
        done, total, r = payload
        if r.address in self._row_widgets:
            w = self._row_widgets[r.address]
            if w.winfo_exists():
                if r.status == "unreachable":
                    w.configure(text="couldn't check", text_color=WARN)
                elif r.balance > 0:
                    w.configure(text=f"{r.balance:.8f} {r.coin}  (${r.usd:,.2f})", text_color=GOOD)
                else:
                    w.configure(text="0", text_color=MUTED)
        self.total_label.configure(text=f"Checking balances… {done}/{total}")

    def _on_bal_done(self, payload):
        results, totals = payload
        for r in results:
            self.balances_by_addr[r.address] = r
        self.total_usd = totals.get("total_usd", 0.0)
        self.check_bal_btn.configure(state="normal", text="💰  Re-check balances")
        self._apply_known_balances()
        self._update_total_label(totals)
        if totals.get("error"):
            messagebox.showwarning("Balance check", "Couldn't reach the balance services:\n" + totals["error"])

    def _apply_known_balances(self):
        for addr, w in self._row_widgets.items():
            r = self.balances_by_addr.get(addr)
            if r and w.winfo_exists():
                if r.status == "unreachable":
                    w.configure(text="couldn't check", text_color=WARN)
                elif r.balance > 0:
                    w.configure(text=f"{r.balance:.8f} {r.coin}  (${r.usd:,.2f})", text_color=GOOD)
                else:
                    w.configure(text="0", text_color=MUTED)

    def _update_total_label(self, totals=None):
        if totals and totals.get("by_coin"):
            parts = []
            for coin, v in totals["by_coin"].items():
                if v["balance"] > 0:
                    parts.append(f"{v['balance']:.6f} {coin}")
            summary = "  ·  ".join(parts) if parts else "no balance found"
            self.total_label.configure(
                text=f"Total found: ${self.total_usd:,.2f}   ({summary})")
        elif self.total_usd:
            self.total_label.configure(text=f"Total found: ${self.total_usd:,.2f}")
        else:
            self.total_label.configure(text="")

    # ------------------------------------------------- export / copy / clear
    def _export_report(self):
        if not self.findings:
            messagebox.showinfo("Nothing to export", "Scan a drive first.")
            return
        reveal = messagebox.askyesno(
            "Include secrets?",
            "Include full private keys and seed phrases in the exported report?\n\n"
            "Choose NO to keep them masked (safer).\n"
            "Choose YES only if you will store the file somewhere safe and offline.")
        path = filedialog.asksaveasfilename(
            title="Save report", defaultextension=".html",
            initialfile="wallet-finder-report.html",
            filetypes=[("HTML report", "*.html"), ("Text report", "*.txt"),
                       ("JSON report", "*.json")])
        if not path:
            return
        try:
            if path.endswith(".json"):
                report.export_json(self.findings, path, include_secrets=reveal)
            elif path.endswith(".txt"):
                report.export_text(self.findings, path, include_secrets=reveal)
            else:
                report.export_html(self.findings, path, include_secrets=reveal,
                                   balances_total=self.total_usd or None)
            messagebox.showinfo("Saved", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _copy_safe(self, loc):
        src = loc.split(" @ ")[0].split(" (raw")[0]
        dest = filedialog.askdirectory(title="Choose a safe folder to copy the wallet into")
        if not dest:
            return
        try:
            out = report.copy_to_safe_folder(src, dest)
            messagebox.showinfo("Backed up", f"Copied to:\n{out}")
        except Exception as e:
            messagebox.showerror("Copy failed", str(e))

    def _clear_results(self):
        if messagebox.askyesno("Clear results", "Remove all current findings from the list?"):
            self.findings = []
            self.balances_by_addr = {}
            self.total_usd = 0.0
            self.show_results()

    # ----------------------------------------------- static info screens
    def _text_screen(self, title, body):
        self._clear_main()
        s = self._scroll()
        ctk.CTkLabel(s, text=title, font=F(28, "bold"), text_color=TEXT,
                     anchor="w").pack(fill="x", pady=(2, 12))
        card = self._card(s)
        box = ctk.CTkTextbox(card, font=ctk.CTkFont(family="Segoe UI", size=15),
                             fg_color=CARD, text_color=TEXT, wrap="word", height=560,
                             activate_scrollbars=True)
        box.pack(fill="both", expand=True, padx=14, pady=14)
        box.insert("1.0", body)
        box.configure(state="disabled")

    def show_hardware(self):
        self._text_screen("Connecting old drives", content.HARDWARE_GUIDE)

    def show_help(self):
        self._text_screen("Next steps — what to do with your finds", content.NEXT_STEPS)

    def show_about(self):
        self._clear_main()
        s = self._scroll()
        ctk.CTkLabel(s, text="About & safety", font=F(28, "bold"), text_color=TEXT,
                     anchor="w").pack(fill="x", pady=(2, 10))
        self._notice(s, "Only for drives you own", content.OWNERSHIP_NOTICE, WARN)
        self._notice(s, "Your keys stay on this computer", content.PRIVACY_NOTICE, ACCENT)
        c = self._card(s)
        ctk.CTkLabel(c, text=content.ABOUT, font=F(15), text_color=TEXT, justify="left",
                     wraplength=760, anchor="w").pack(fill="x", padx=20, pady=18)
        c2 = self._card(s)
        ctk.CTkLabel(c2, text="What this tool will NOT do", font=F(18, "bold"),
                     text_color=TEXT, anchor="w").pack(fill="x", padx=20, pady=(16, 4))
        for t in ["• It never writes to the drive you scan (read-only).",
                  "• It never sends your private keys, seeds or wallet files anywhere.",
                  "• It cannot send, sweep or move any coins — you do that yourself in the official wallet.",
                  "• It will not try to crack or guess wallet passwords."]:
            ctk.CTkLabel(c2, text=t, font=F(15), text_color=TEXT, justify="left",
                         wraplength=740, anchor="w").pack(fill="x", padx=20, pady=2)
        ctk.CTkLabel(c2, text="", font=F(6)).pack()


def main():
    app = WalletFinderApp()
    app.mainloop()


if __name__ == "__main__":
    main()
