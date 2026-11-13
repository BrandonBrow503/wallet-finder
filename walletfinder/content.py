"""Plain-language in-app text: hardware guide, next-steps help, and notices.

Written for a non-technical reader on a phone-sized screen.
"""

TAGLINE = "Recover crypto from your own old drives."

OWNERSHIP_NOTICE = (
    "Only for drives you own. This tool is for recovering YOUR OWN coins from "
    "your own old drives (and your family's, with their OK). If coins turn up "
    "on a drive that belongs to someone else, they are still that person's "
    "property — return them, don't take them."
)

PRIVACY_NOTICE = (
    "Your keys never leave this computer. Scanning is read-only and never "
    "writes to the drive you are checking. If you turn on balance checking, "
    "ONLY public addresses are sent to a public blockchain website — never "
    "your private keys, seed phrases or wallet files. This tool can never "
    "send or move your coins."
)

BALANCE_CONSENT = (
    "Check balances online?\n\n"
    "To show how much each wallet holds, this tool will look up your PUBLIC "
    "addresses on free public blockchain websites (mempool.space, "
    "litecoinspace.org, blockchair.com) and prices on coingecko.com.\n\n"
    "Only public addresses go online. Your private keys, seed phrases and "
    "wallet files are NEVER sent anywhere. You can turn this off any time."
)

HARDWARE_GUIDE = """\
CONNECTING OLD DRIVES — a plain guide

The easiest fix for almost everything
  A "SATA/IDE-to-USB adapter kit" with its own power supply (about $20 online)
  lets you plug nearly any bare drive into your PC's USB port. Get one that
  lists BOTH SATA and IDE and comes with a power brick. This handles most of
  what's in an attic.

The kinds of drives you might find
  • 3.5" IDE/PATA hard drive (old desktop drive, wide ribbon-cable connector
    with 2 rows of pins, plus a 4-pin power plug). Needs the IDE side of the
    adapter kit and the power brick.
  • 2.5" IDE/PATA laptop drive (smaller, 44-pin). Needs a 2.5" IDE adapter
    (often included in kits). These are powered over the adapter.
  • 3.5" / 2.5" SATA drive (newer, small L-shaped connectors). Use the SATA
    side of the kit; 3.5" needs the power brick, most 2.5" are USB-powered.
  • USB sticks / thumb drives — just plug in. Try every one, even tiny old ones.
  • SD / microSD / CompactFlash cards — use a cheap USB card reader. CF cards
    need a CF reader specifically.
  • Floppy disks (3.5") — get a USB floppy drive (about $15). 5.25" floppies
    need a specialist; set those aside.
  • Zip disks, external enclosures — pull the drive out of a dead enclosure and
    connect it directly with the adapter kit.

Apple / Mac drives
  Old Mac drives are usually formatted HFS+ (or APFS on newer ones). Windows
  can't read HFS+ on its own. Two options: (1) connect the drive to a Mac and
  scan there, or (2) on Windows, install a free/trial HFS reader so the drive
  shows up as a normal letter, then scan it. The scan itself works the same.

VERY IMPORTANT — if a drive CLICKS, buzzes, or spins up and down:
  STOP. Unplug it. A clicking drive is failing and every extra minute can
  destroy the data for good. Don't keep retrying it. Either:
    • Make a one-time image of it first (see "Image a drive" in the app), or
    • Take it to a data-recovery professional.
  The same goes for a drive that smells burnt or was water-damaged.

Good habits
  • Label each drive as you go so you know which you've checked.
  • For a precious or shaky drive, make a disk image first and scan the image —
    that way you only read the old drive once.
"""

NEXT_STEPS = """\
WHAT TO DO WITH WHAT YOU FOUND

General rule
  This tool never moves coins — on purpose. To actually use a recovered wallet
  you import it into the official, trusted wallet software yourself, on a safe
  computer, ideally offline. Download that software ONLY from its official site.

Bitcoin Core wallet.dat
  Install Bitcoin Core (bitcoincore.org). Copy the wallet.dat into its data
  folder (or use File → Open Wallet in newer versions). If it's ENCRYPTED
  (we marked it "needs password"), you must supply the original password —
  there is no way around it and this tool does not try to crack it.

Electrum wallet (default_wallet)
  Install Electrum (electrum.org). Open it with File → Open and point it at the
  file. Enter the wallet password if asked.

A seed phrase (12/18/24 words)
  You can restore this into most modern wallets (Electrum, a hardware wallet,
  etc.) using "Restore from seed / recovery phrase". Guard this phrase like
  cash — anyone with it controls the coins.

A WIF private key (starts 5, K or L)
  In Electrum choose "Import Bitcoin addresses or private keys". Litecoin/
  Dogecoin keys go into their own Core wallet via importprivkey.

Ethereum keystore (UTC--... JSON)
  Import into MetaMask or MyEtherWallet with the keystore file + its password.

MultiBit / Armory / Blockchain.info backup
  These are older formats. MultiBit Classic is retired — export the private
  keys from it if you still can, or use its .key file with a converter.
  Blockchain.info backups (wallet.aes.json) are restored on blockchain.com
  with your original password.

Encrypted wallet, lost password
  This tool will not crack passwords. If the wallet is encrypted and you don't
  have the password, the coins are effectively locked. Try your old passwords
  first; there are reputable specialist recovery services as a last resort.

Safety
  • Watch out for fake "wallet recovery" services and anyone asking for your
    seed or keys — never share them.
  • Move funds only after you fully control the destination wallet.
"""

ABOUT = """\
Wallet Finder reads your old drives looking for forgotten cryptocurrency
wallets and keys, so you can recover your own coins. It is read-only: it never
changes the drive it scans, and it can never send or move money. You do the
final step yourself in the official wallet software.
"""
