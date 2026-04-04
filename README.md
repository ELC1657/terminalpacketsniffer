# Terminal Packet Sniffer `v0.12`

A terminal-based network packet sniffer with a live TUI showing real-time traffic and automatic security alerts.

![Version](https://img.shields.io/badge/version-0.12-orange) ![Python](https://img.shields.io/badge/python-3.8+-blue) ![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)

## Features

- Live packet feed; TCP, UDP, DNS, HTTP, ICMP
- Security alerts panel with risk explanations and fixes
- Top Talkers panel showing the busiest IPs with traffic bars
- 5 built-in themes (press `t` to cycle)
- Filters by protocol, host, or port

## Install

**Requirements:** Python 3.8+, macOS or Linux

```bash
git clone https://github.com/ELC1657/terminalpacketsniffer.git
cd terminalpacketsniffer
sudo ./install
```

That's it. The install script handles everything virtual environment, dependencies, and registering the command globally. No manual pip installs needed.

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
| `t` | Cycle through 5 themes |
| `p` | Pause / resume capture |
| `c` | Clear both panels |
| `q` | Quit |

## Themes

| # | Name | Style |
|---|------|-------|
| 1 | Default Dark | Blue/teal |
| 2 | Nord | Cool icy blues |
| 3 | Gruvbox | Warm earthy tones |
| 4 | Catppuccin | Soft purples and pinks |
| 5 | Dracula | Classic hacker purple/green |

## Security Alerts

The right panel automatically detects and explains:

| Severity | Alert |
|----------|-------|
| CRITICAL | Telnet traffic (unencrypted remote access) |
| HIGH | Cleartext HTTP, FTP |
| MEDIUM | Port scans, ICMP floods, DNS tunneling |
| LOW | RST floods |

Each alert includes a **Risk** explanation and a **Fix** recommendation on first occurrence.

## Notes

- Requires `sudo` — raw packet capture needs root privileges
- The `venv/` directory is created locally and not included in the repo
- Tested on macOS and Linux
