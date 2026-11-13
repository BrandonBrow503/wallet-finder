#!/usr/bin/env bash
# Build the Windows .exe on a WINDOWS machine (recommended) or via Wine on Linux.
#
# ON WINDOWS (simplest, most reliable):
#   1. Install Python 3.12 from python.org (tick "Add python.exe to PATH").
#   2. Open Command Prompt in this folder and run:
#        py -m pip install customtkinter pyinstaller
#        py -m PyInstaller --noconfirm --clean --onefile --windowed --name WalletFinder ^
#           --collect-data customtkinter ^
#           --add-data "walletfinder/data/bip39_english.txt;walletfinder/data" ^
#           --hidden-import tkinter main.py
#   3. The .exe appears in dist\WalletFinder.exe
#
# CROSS-BUILD ON LINUX VIA WINE (what produced the shipped .exe):
#   sudo apt-get install -y wine wine64 wine32
#   export WINEPREFIX=$PWD/.winebuild WINEARCH=win64
#   wineboot --init
#   wine python-3.12.x-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_tcltk=1
#   wine 'C:\Python312\python.exe' -m pip install customtkinter pyinstaller
#   wine 'C:\Python312\python.exe' -m PyInstaller --noconfirm --clean --onefile --windowed \
#        --name WalletFinder --collect-data customtkinter \
#        --add-data "walletfinder/data/bip39_english.txt;walletfinder/data" \
#        --hidden-import tkinter main.py
echo "See the comments in this file for Windows build steps."
