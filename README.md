# Terminal Packet Sniffer `v0.25.0`

A terminal-based network packet sniffer with a live TUI showing real-time traffic, automatic security alerts, and an interactive packet detail browser.

![Version](https://img.shields.io/badge/version-0.25.0-orange) ![Python](https://img.shields.io/badge/python-3.8+-blue) ![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)

## Features

**Protocol Support**
- Live packet feed: TCP, UDP, DNS, HTTP, ICMP, ARP, TLS, IPv6
- TLS SNI extraction : see which HTTPS hostnames are being visited without decryption
- ARP monitoring : displays who-has/is-at and detects ARP spoofing attacks
- UDP payload snippets : shows decoded payload alongside UDP packets
- Full ICMP type decoding : TTL Exceeded, Redirect, Timestamp, and more
- IPv6 support : handles IPv6 packets across both the TUI and CLI sniffer

**Security Alerts**
- Real-time detection with risk explanations and fix recommendations
- Cleartext protocol detection (HTTP, Telnet, FTP)
- Port scan, RST flood, and ICMP flood detection
- DNS tunneling and DNS exfiltration rate detection
- SYN half-open (stealth) scan detection
- ARP spoofing detection (multiple MACs claiming same IP)
- New LAN host alerts (IPv4 and IPv6 private ranges)
- All detections also available in the CLI sniffer (`sniffer.py`)

**Packet Detail Browser**
- Press `d` to enter browse mode ; freezes the packet log and shows the full Scapy layer dump
- Step backward and forward through captured packets with `[` and `]`
- Selected packet is highlighted in the live log with the current theme color
- Press `d` again to exit and resume live streaming

**PCAP Support**
- `w` : export the current packet buffer to a timestamped `.pcap` file (TUI)
- `-r / --read file.pcap` : replay a saved capture file offline in both the TUI and CLI sniffer
- `-w / --write file.pcap` : save live capture to a PCAP file (CLI sniffer)

**Performance**
- Packet queue with configurable display speed (Slow / Normal / Fast)
- Batched rendering : UI stays responsive under high traffic
- All widget references cached — no DOM queries in the hot path
- Configurable packet buffer size via `--buffer N`

**UI**
- 9 built-in themes (press `t` to cycle)
- Top Talkers panel with live traffic bars and provider labels
- Stats bar showing per-protocol counts, speed, bandwidth, and browse position
- Pause, clear, and quit without lag

**Compatibility**
- macOS Wi-Fi compatible : capture works on en0 without requiring promiscuous mode
- In-TUI error notifications if capture fails to start (permission denied, bad interface, etc.)
- Installer bakes in absolute paths so the global command works from any directory after `sudo ./install`

## Install

**Requirements:** Python 3.8+, macOS or Linux

```bash
git clone https://github.com/ELC1657/terminalpacketsniffer.git
cd terminalpacketsniffer
sudo ./install
```

The install script handles everything: virtual environment, dependencies, and registering the command globally. No manual pip installs needed.

> **Migrating to a new machine?** Always delete the `venv/` folder before running `sudo ./install` on a new machine — virtualenvs are not portable between systems.

## Run

```bash
packetsniffer
```

### Options

```bash
packetsniffer -i en0              # specific network interface
packetsniffer -p dns              # filter by protocol (tcp/udp/icmp/dns/http)
packetsniffer --host 8.8.8.8      # filter by IP
packetsniffer --port 443          # filter by port
packetsniffer -r capture.pcap     # replay a saved PCAP file
packetsniffer --buffer 1000       # increase packet browser buffer (default: 500)
packetsniffer --cli               # use the plain terminal sniffer instead of the TUI
```

### CLI sniffer options

```bash
packetsniffer --cli -i en0              # specific interface
packetsniffer --cli -p dns              # filter by protocol
packetsniffer --cli -r capture.pcap     # replay a PCAP file
packetsniffer --cli -w out.pcap         # save capture to file
packetsniffer --cli --buffer 5000       # cap in-memory packet storage (default: 10000)
packetsniffer --cli -c 100              # stop after 100 packets
packetsniffer --cli -v                  # verbose: raw Scapy layer dump
```

## Keybindings

| Key | Action |
|-----|--------|
| `d` | Enter / exit packet detail browse mode |
| `[` | Previous packet (browse mode) |
| `]` | Next packet (browse mode) |
| `w` | Export packet buffer to a `.pcap` file |
| `s` | Cycle display speed (Slow / Normal / Fast) |
| `t` | Cycle through 9 themes |
| `p` | Pause / resume capture |
| `c` | Clear all panels |
| `q` | Quit |

## Themes

| # | Name | Style |
|---|------|-------|
| 1 | Default Dark | Blue/teal |
| 2 | Nord | Cool icy blues |
| 3 | Gruvbox | Warm earthy tones |
| 4 | Catppuccin | Soft purples and pinks |
| 5 | Dracula | Classic hacker purple/green |
| 6 | Tokyo Night | Deep blue/purple night |
| 7 | Monokai | High-contrast classic |
| 8 | Rose Pine | Warm muted pastels |
| 9 | Matrix | Bright green on black |

## Security Alerts

The right panel automatically detects and explains:

| Severity | Alert |
|----------|-------|
| CRITICAL | Telnet traffic (unencrypted remote access), ARP spoofing |
| HIGH | Cleartext HTTP, FTP, DNS exfiltration rate, SYN half-open scan, suspicious DNS |
| MEDIUM | Port scans, ICMP floods, DNS tunneling |
| LOW | RST floods, new LAN host detected |

Each alert includes a **Risk** explanation and a **Fix** recommendation on first occurrence. Repeated alerts are deduplicated and show a count badge. The CLI sniffer prints the same alerts inline with an `[ALERT SEVERITY]` prefix.

## Troubleshooting

**No packets appear after launching**
- Make sure you are running via `packetsniffer` (not `python3 sniffer_tui.py` directly) — the launcher handles `sudo` automatically
- A red notification in the TUI will tell you if capture failed to start and why
- On macOS, specify the interface explicitly: `packetsniffer -i en0`

**"Cannot set promiscuous mode" error**
- This is a macOS restriction on Wi-Fi interfaces and is handled automatically in v0.25.0 — update and reinstall

**Global command uses wrong paths after moving to a new machine**
- Delete the old venv: `rm -rf venv`
- Re-run the installer from the project directory: `sudo ./install`
- This bakes the correct absolute paths into the global command

**The `venv/` from another machine doesn't work**
- Virtualenvs are not portable. Always rebuild: `rm -rf venv && sudo ./install`

## Notes

- Requires `sudo` — raw packet capture needs root privileges
- The `venv/` directory is created locally and not included in the repo
- Tested on macOS (Intel and Apple Silicon) and Linux
- Packet detail browser holds the last 500 packets in memory by default (configurable with `--buffer`)
- PCAP exports are written to the current working directory with a timestamp filename
