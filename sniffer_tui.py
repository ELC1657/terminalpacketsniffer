#!/usr/bin/env python3
"""
Packet Sniffer TUI — live traffic + security alerts + top talkers
Run with: sudo venv/bin/python sniffer_tui.py [-i INTERFACE] [-p PROTOCOL] [--host IP] [--port PORT]
"""

import argparse
import threading
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("scapy not found — run: pip install scapy")
    exit(1)

try:
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, RichLog, Static
    from textual.containers import Horizontal, Vertical
    from rich.text import Text
except ImportError:
    print("textual not found — run: pip install textual")
    exit(1)


# ── Severity → color ──────────────────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "cyan",
    "INFO":     "dim white",
}

# ── Alert explanations ────────────────────────────────────────────────────────
# Each entry: (risk explanation, recommended fix)
ALERT_INFO: dict[str, tuple[str, str]] = {
    "Cleartext HTTP": (
        "Passwords, session cookies, and form data travel in plain text. "
        "Anyone on your network can read or modify them in real time (MITM).",
        "Switch to HTTPS (port 443). HTTP should never carry sensitive data.",
    ),
    "Telnet (cleartext)": (
        "Every keystroke — including your password — is sent unencrypted. "
        "A single packet capture is enough to steal credentials.",
        "Replace Telnet with SSH immediately. There is no safe use of Telnet.",
    ),
    "FTP (cleartext)": (
        "Login credentials and all transferred file contents are visible in "
        "plain text on the wire. Trivial to intercept.",
        "Use SFTP or FTPS instead. Most modern servers support both.",
    ),
    "Port Scan": (
        "An IP is probing many ports in rapid succession — the classic first "
        "step of an attack to map what services are running on your network.",
        "Block the source IP at your firewall. Check if it's an internal host "
        "running a misconfigured scanner.",
    ),
    "RST Flood / Scan": (
        "A flood of TCP RST packets often signals a stealth (half-open) scan "
        "or an attempt to disrupt existing connections.",
        "Rate-limit RST packets at the firewall. Investigate the source IP.",
    ),
    "ICMP Flood": (
        "High ICMP volume can be network reconnaissance (mapping hosts) or "
        "a ping-flood DoS attack trying to saturate bandwidth.",
        "Rate-limit ICMP at your router/firewall. Block the source if external.",
    ),
    "Suspicious DNS": (
        "A DNS query contains keywords associated with tracking, C2 servers, "
        "or malware infrastructure. Could indicate an infected host phoning home.",
        "Block the domain at your DNS resolver. Inspect the querying device for "
        "malware.",
    ),
    "Possible DNS Tunnel": (
        "Unusually long DNS labels are a classic sign of DNS tunneling — a "
        "technique used to exfiltrate data or bypass firewalls by encoding "
        "traffic inside DNS queries.",
        "Inspect DNS traffic from this host closely. Block long-label queries "
        "at your DNS firewall if tunneling is confirmed.",
    ),
}

# ── Known IP prefixes ─────────────────────────────────────────────────────────
_IP_OWNERS = [
    ("192.168.", "LAN"),   ("10.",      "LAN"),   ("172.16.", "LAN"),
    ("17.",      "Apple"), ("104.18.",  "Cloudflare"), ("172.65.", "Cloudflare"),
    ("172.67.",  "Cloudflare"), ("140.82.", "GitHub"),  ("185.199.", "GitHub"),
    ("64.233.",  "Google"), ("142.250.", "Google"), ("216.58.", "Google"),
    ("34.",      "GCloud"), ("35.",      "GCloud"),
    ("52.",      "AWS"),   ("54.",      "AWS"),   ("13.",     "AWS"),
    ("151.101.", "Fastly"), ("23.",      "Akamai"),
]

def _ip_owner(ip: str) -> str:
    for prefix, name in _IP_OWNERS:
        if ip.startswith(prefix):
            return name
    return "?"


class SnifferApp(App):
    CSS = """
    Screen { layout: vertical; background: $surface; }

    #body {
        layout: horizontal;
        height: 1fr;
    }

    /* ── left: live packets ── */
    #left {
        width: 58%;
        border: tall $primary;
        padding: 0 1;
    }

    /* ── right: alerts + talkers stacked ── */
    #right {
        layout: vertical;
        width: 42%;
    }

    #alerts-pane {
        height: 2fr;
        border: tall $error;
        padding: 0 1;
    }

    #talkers-pane {
        height: 1fr;
        border: tall $success;
        padding: 0 1;
    }

    /* ── bottom stats bar ── */
    #stats {
        height: 1;
        background: $primary-darken-3;
        color: $text-muted;
        padding: 0 2;
        content-align: left middle;
    }
    """

    BINDINGS = [
        ("q",       "quit",       "Quit"),
        ("c",       "clear_all",  "Clear"),
        ("p",       "pause",      "Pause"),
        ("t",       "next_theme", "Theme"),
    ]

    THEMES = [
        ("textual-dark",     "Default Dark"),
        ("nord",             "Nord"),
        ("gruvbox",          "Gruvbox"),
        ("catppuccin-mocha", "Catppuccin"),
        ("dracula",          "Dracula"),
    ]

    def __init__(self, interface=None, bpf_filter=None):
        super().__init__()
        self.interface   = interface
        self.bpf_filter  = bpf_filter
        self.paused      = False
        self._theme_idx  = 0

        self.stats: dict[str, int] = defaultdict(int)
        self._alert_seen: dict[str, int] = defaultdict(int)

        # detection trackers
        self._syn_ports:  dict[str, set] = defaultdict(set)
        self._rst_count:  dict[str, int] = defaultdict(int)
        self._icmp_count: dict[str, int] = defaultdict(int)

        # top talkers: ip → packet count
        self._ip_count: dict[str, int] = defaultdict(int)

    # ── Layout ────────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield RichLog(id="pkt-log", highlight=False, markup=False, wrap=False)
            with Vertical(id="right"):
                with Vertical(id="alerts-pane"):
                    yield RichLog(id="alert-log", highlight=False, markup=False, wrap=False)
                with Vertical(id="talkers-pane"):
                    yield Static("", id="talkers")
        yield Static("", id="stats")
        yield Footer()

    def on_mount(self) -> None:
        self.title     = "Packet Sniffer"
        self.sub_title = f"iface: {self.interface or 'auto'} | filter: {self.bpf_filter or 'all'}"

        self.query_one("#left").border_title         = "  Live Packets"
        self.query_one("#alerts-pane").border_title  = "  Security Alerts"
        self.query_one("#talkers-pane").border_title = "  Top Talkers"

        threading.Thread(target=self._sniff_thread, daemon=True).start()
        self.set_interval(1.0, self._refresh_stats)
        self.set_interval(2.0, self._refresh_talkers)

    # ── Sniff thread ──────────────────────────────────────────────────────────
    def _sniff_thread(self) -> None:
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=lambda pkt: self.call_from_thread(self._on_packet, pkt),
            store=False,
        )

    # ── Packet handler ────────────────────────────────────────────────────────
    def _on_packet(self, pkt) -> None:
        if self.paused or IP not in pkt:
            return

        self.stats["Total"] += 1
        src = pkt[IP].src
        dst = pkt[IP].dst
        ts  = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        log = self.query_one("#pkt-log", RichLog)

        self._ip_count[src] += 1
        self._ip_count[dst] += 1

        # ── TCP ───────────────────────────────────────────────────────────────
        if TCP in pkt:
            self.stats["TCP"] += 1
            sp, dp = pkt[TCP].sport, pkt[TCP].dport
            flags  = str(pkt[TCP].flags)

            if HTTPRequest in pkt:
                self.stats["HTTP"] += 1
                method = pkt[HTTPRequest].Method.decode(errors="ignore")
                host   = (pkt[HTTPRequest].Host or b"").decode(errors="ignore") or dst
                path   = (pkt[HTTPRequest].Path or b"/").decode(errors="ignore")
                log.write(Text.assemble(
                    ("HTTP REQ  ", "bold green"),
                    (f"{ts}  ", "dim white"),
                    (f"{src}:{sp} → {dst}:{dp}", "white"),
                    (f"\n          {method} {host}{path}", "green"),
                ))
                self._alert("HIGH", "Cleartext HTTP", f"{src}  {method} {host}{path}")
                return

            if HTTPResponse in pkt:
                self.stats["HTTP"] += 1
                code = getattr(pkt[HTTPResponse], "Status_Code", b"?")
                if isinstance(code, bytes):
                    code = code.decode(errors="ignore")
                log.write(Text.assemble(
                    ("HTTP RES  ", "bold green"),
                    (f"{ts}  ", "dim white"),
                    (f"{src}:{sp} → {dst}:{dp}  status={code}", "white"),
                ))
                return

            for port, name, sev in ((23, "Telnet", "CRITICAL"), (21, "FTP", "HIGH")):
                if sp == port or dp == port:
                    self._alert(sev, f"{name} (cleartext)", f"{src}:{sp} → {dst}:{dp}")

            if "S" in flags and "A" not in flags:
                self._syn_ports[src].add(dp)
                n = len(self._syn_ports[src])
                if n in (15, 50, 100):
                    self._alert("MEDIUM", "Port Scan", f"{src} SYN'd {n} distinct ports")

            if "R" in flags:
                self._rst_count[src] += 1
                c = self._rst_count[src]
                if c in (25, 100):
                    self._alert("LOW", "RST Flood / Scan", f"{src} sent {c} RST packets")

            row = Text.assemble(
                ("TCP       ", "bold cyan"),
                (f"{ts}  ", "dim white"),
                (f"{src}:{sp} → {dst}:{dp}  ", "white"),
                (f"flags={flags}", "dim cyan"),
            )
            if Raw in pkt:
                snippet = pkt[Raw].load[:70].decode("utf-8", errors="ignore").replace("\n", " ").strip()
                if snippet:
                    row.append(f"\n          {snippet[:70]}", style="dim white")
            log.write(row)
            return

        # ── UDP / DNS ─────────────────────────────────────────────────────────
        if UDP in pkt:
            self.stats["UDP"] += 1
            sp, dp = pkt[UDP].sport, pkt[UDP].dport

            if DNS in pkt:
                self.stats["DNS"] += 1
                dns = pkt[DNS]
                if dns.qr == 0 and DNSQR in pkt:
                    name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    log.write(Text.assemble(
                        ("DNS QRY   ", "bold magenta"),
                        (f"{ts}  ", "dim white"),
                        (f"{src} → ", "white"),
                        (name, "magenta"),
                    ))
                    self._check_dns(src, name)
                    return
                if dns.qr == 1 and DNSRR in pkt:
                    name  = pkt[DNSRR].rrname.decode(errors="ignore").rstrip(".")
                    rdata = getattr(pkt[DNSRR], "rdata", "?")
                    log.write(Text.assemble(
                        ("DNS RPL   ", "bold magenta"),
                        (f"{ts}  ", "dim white"),
                        (f"{name} → {rdata}", "white"),
                    ))
                    return

            log.write(Text.assemble(
                ("UDP       ", "bold yellow"),
                (f"{ts}  ", "dim white"),
                (f"{src}:{sp} → {dst}:{dp}", "white"),
            ))
            return

        # ── ICMP ──────────────────────────────────────────────────────────────
        if ICMP in pkt:
            self.stats["ICMP"] += 1
            self._icmp_count[src] += 1
            kind = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}.get(
                pkt[ICMP].type, f"type={pkt[ICMP].type}"
            )
            log.write(Text.assemble(
                ("ICMP      ", "bold red"),
                (f"{ts}  ", "dim white"),
                (f"{src} → {dst}  {kind}", "white"),
            ))
            c = self._icmp_count[src]
            if c in (30, 100):
                self._alert("MEDIUM", "ICMP Flood", f"{src} sent {c} ICMP packets")

    # ── DNS heuristics ────────────────────────────────────────────────────────
    def _check_dns(self, src: str, name: str) -> None:
        BAD_KEYWORDS = {"track", "beacon", "telemetry", "c2", "cnc",
                        "botnet", "malware", "exfil", "keylog"}
        for kw in BAD_KEYWORDS:
            if kw in name.lower():
                self._alert("HIGH", "Suspicious DNS", f"{src} → {name}")
                return
        if any(len(l) > 40 for l in name.split(".")):
            self._alert("MEDIUM", "Possible DNS Tunnel", f"{src} → {name[:80]}")

    # ── Alert writer ──────────────────────────────────────────────────────────
    def _alert(self, severity: str, title: str, detail: str) -> None:
        key = f"{severity}|{title}"
        self._alert_seen[key] += 1
        n = self._alert_seen[key]

        if n > 1 and n not in (5, 25, 100):
            return

        self.stats["Alerts"] += 1
        alog  = self.query_one("#alert-log", RichLog)
        color = SEV_COLOR.get(severity, "white")
        ts    = datetime.now().strftime("%H:%M:%S")
        badge = f" ×{n}" if n > 1 else ""

        # base header + detail
        msg = Text.assemble(
            (f" {severity} ", color),
            (f" {ts}{badge}\n", "dim white"),
            (f" {title}\n",     f"bold {color.split()[-1]}"),
            (f" {detail}\n",    "white"),
        )

        # explanation block (only on first occurrence)
        if n == 1 and title in ALERT_INFO:
            risk, fix = ALERT_INFO[title]
            msg.append("\n Risk  ", style="bold yellow")
            msg.append(risk + "\n", style="dim white")
            msg.append(" Fix   ", style="bold green")
            msg.append(fix + "\n", style="dim white")

        msg.append("─" * 40 + "\n", style="dim white")
        alog.write(msg)

    # ── Top Talkers panel ─────────────────────────────────────────────────────
    def _refresh_talkers(self) -> None:
        if not self._ip_count:
            return

        top = sorted(self._ip_count.items(), key=lambda x: -x[1])[:6]
        max_count = top[0][1] or 1
        bar_w = 10

        out = Text()
        for ip, count in top:
            filled  = int((count / max_count) * bar_w)
            bar     = "█" * filled + "░" * (bar_w - filled)
            owner   = _ip_owner(ip)
            out.append(f" {ip:<17}", style="white")
            out.append(bar, style="green")
            out.append(f"  {count:>5}  ", style="dim white")
            out.append(f"{owner}\n", style="cyan")

        self.query_one("#talkers", Static).update(out)

    # ── Stats bar ─────────────────────────────────────────────────────────────
    def _refresh_stats(self) -> None:
        paused = "  [PAUSED]" if self.paused else ""
        parts  = "   ".join(f"{k}: {v}" for k, v in self.stats.items())
        self.query_one("#stats", Static).update(f"  {parts}{paused}")

    # ── Key actions ───────────────────────────────────────────────────────────
    def action_clear_all(self) -> None:
        self.query_one("#pkt-log",   RichLog).clear()
        self.query_one("#alert-log", RichLog).clear()

    def action_pause(self) -> None:
        self.paused = not self.paused

    def action_next_theme(self) -> None:
        self._theme_idx = (self._theme_idx + 1) % len(self.THEMES)
        name, label = self.THEMES[self._theme_idx]
        self.theme = name
        self.notify(f"Theme: {label}", timeout=2)


# ── CLI ───────────────────────────────────────────────────────────────────────
def build_bpf(args) -> str | None:
    parts = []
    if args.protocol:
        mapping = {
            "tcp": "tcp", "udp": "udp", "icmp": "icmp",
            "dns": "udp port 53",
            "http": "tcp port 80 or tcp port 8080",
        }
        parts.append(mapping[args.protocol])
    if args.port:
        parts.append(f"port {args.port}")
    if args.host:
        parts.append(f"host {args.host}")
    return " and ".join(parts) or None


def main():
    ap = argparse.ArgumentParser(description="Packet Sniffer TUI")
    ap.add_argument("-i", "--interface")
    ap.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp", "dns", "http"])
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    args = ap.parse_args()

    SnifferApp(
        interface=args.interface,
        bpf_filter=build_bpf(args),
    ).run()


if __name__ == "__main__":
    main()
