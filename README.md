# Terminal Packet Sniffer `v0.20.0`

A terminal-based network packet sniffer with a live TUI showing real-time traffic, automatic security alerts, and an interactive packet detail browser.

![Version](https://img.shields.io/badge/version-0.20.0-orange) ![Python](https://img.shields.io/badge/python-3.8+-blue) ![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)

## Features

**Protocol Support**
- Live packet feed: TCP, UDP, DNS, HTTP, ICMP, ARP, TLS
- TLS SNI extraction : see which HTTPS hostnames are being visited without decryption
- ARP monitoring : displays who-has/is-at and detects ARP spoofing attacks
- UDP payload snippets : shows decoded payload alongside UDP packets
- Full ICMP type decoding : TTL Exceeded, Redirect, Timestamp, and more

**Security Alerts**
- Real-time detection with risk explanations and fix recommendations
- Cleartext protocol detection (HTTP, Telnet, FTP)
- Port scan, RST flood, and ICMP flood detection
- DNS tunneling and DNS exfiltration rate detection
- SYN half-open (stealth) scan detection
- ARP spoofing detection (multiple MACs claiming same IP)
- New LAN host alerts

**Packet Detail Browser**
- Press `d` to enter browse mode ; freezes the packet log and shows the full Scapy layer dump
- Step backward and forward through the last 500 captured packets with `[` and `]`
- Selected packet is highlighted in the live log with the current theme color
- Press `d` again to exit and resume live streaming

**Performance**
- Packet queue with configurable display speed (Slow / Normal / Fast)
- Batched rendering : UI stays responsive under high traffic
- All widget references cached — no DOM queries in the hot path

**UI**
- 9 built-in themes (press `t` to cycle)
- Top Talkers panel with live traffic bars and provider labels
- Stats bar showing per-protocol counts, speed, and browse position
- Pause, clear, and quit without lag

## Install

**Requirements:** Python 3.8+, macOS or Linux

```bash
git clone https://github.com/ELC1657/terminalpacketsniffer.git
cd terminalpacketsniffer
sudo ./install
```

The install script handles everything; virtual environment, dependencies, and registering the command globally. No manual pip installs needed.

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
```

## Keybindings

| Key | Action |
|-----|--------|
| `d` | Enter / exit packet detail browse mode |
| `[` | Previous packet (browse mode) |
| `]` | Next packet (browse mode) |
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

Each alert includes a **Risk** explanation and a **Fix** recommendation on first occurrence. Repeated alerts are deduplicated and show a count badge.

## Notes

- Requires `sudo` — raw packet capture needs root privileges
- The `venv/` directory is created locally and not included in the repo
- Tested on macOS and Linux
- Packet detail browser holds the last 500 packets in memory
