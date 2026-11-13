#!/usr/bin/env bash
# Build the Linux executable with PyInstaller.
set -e
python3 -m venv .venv && . .venv/bin/activate
pip install -U pip customtkinter pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name WalletFinder \
  --collect-data customtkinter \
  --add-data "walletfinder/data/bip39_english.txt:walletfinder/data" \
  --hidden-import tkinter main.py
echo "Built dist/WalletFinder"
