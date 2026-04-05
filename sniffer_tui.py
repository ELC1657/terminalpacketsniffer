#!/usr/bin/env python3

import argparse
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, ARP, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("scapy not found - run: pip install scapy")
    exit(1)

try:
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, RichLog, Static
    from textual.containers import Horizontal, Vertical
    from rich.text import Text
except ImportError:
    print("textual not found - run: pip install textual")
    exit(1)


SEV_COLOR = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "cyan",
    "INFO":     "dim white",
}

ALERT_INFO: dict[str, tuple[str, str]] = {
    "Cleartext HTTP": (
        "Passwords, session cookies, and form data travel in plain text. "
        "Anyone on your network can read or modify them in real time (MITM).",
        "Switch to HTTPS (port 443). HTTP should never carry sensitive data.",
    ),
    "Telnet (cleartext)": (
        "Every keystroke including your password is sent unencrypted. "
        "A single packet capture is enough to steal credentials.",
        "Replace Telnet with SSH immediately. There is no safe use of Telnet.",
    ),
    "FTP (cleartext)": (
        "Login credentials and all transferred file contents are visible in "
        "plain text on the wire. Trivial to intercept.",
        "Use SFTP or FTPS instead. Most modern servers support both.",
    ),
    "Port Scan": (
        "An IP is probing many ports in rapid succession - the classic first "
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
        "Block the domain at your DNS resolver. Inspect the querying device for malware.",
    ),
    "Possible DNS Tunnel": (
        "Unusually long DNS labels are a classic sign of DNS tunneling - a "
        "technique used to exfiltrate data or bypass firewalls by encoding "
        "traffic inside DNS queries.",
        "Inspect DNS traffic from this host closely. Block long-label queries "
        "at your DNS firewall if tunneling is confirmed.",
    ),
    "ARP Spoofing": (
        "Two different MAC addresses are claiming the same IP address. This is "
        "the hallmark of ARP poisoning — an attacker is redirecting traffic "
        "through their machine to intercept or modify it (MITM).",
        "Identify the rogue MAC and block it at the switch. Enable Dynamic ARP "
        "Inspection (DAI) on managed switches to prevent future poisoning.",
    ),
    "DNS Exfil Rate": (
        "A single host is making an abnormally high number of DNS queries per "
        "second. This is a common sign of data exfiltration over DNS or an "
        "infected host beaconing to a C2 server.",
        "Capture and inspect the DNS queries from this host. Block the source "
        "at your DNS firewall and scan the device for malware.",
    ),
    "New LAN Host": (
        "An IP address appeared on your local network that has not been seen "
        "before in this session. Could be a rogue device, a new connection, or "
        "a spoofed address.",
        "Verify the device is authorised. Check your DHCP leases and switch "
        "port tables to identify the physical device.",
    ),
    "SYN Without SYN-ACK": (
        "A host has many TCP connections stuck in SYN-sent state with no "
        "SYN-ACK reply. This is the signature of a stealth (half-open) port "
        "scan — the scanner never completes the handshake to avoid logging.",
        "Block the scanning IP at the firewall. If it is an internal host, "
        "investigate for malware or a misconfigured scanner.",
    ),
}

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

    #left {
        width: 58%;
        border: tall $primary;
        padding: 0 1;
    }

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

    #stats {
        height: 1;
        background: $primary-darken-3;
        color: $text-muted;
        padding: 0 2;
        content-align: left middle;
    }
    """

    BINDINGS = [
        ("q", "quit",       "Quit"),
        ("c", "clear_all",  "Clear"),
        ("p", "pause",      "Pause"),
        ("t", "next_theme", "Theme"),
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
        self.interface  = interface
        self.bpf_filter = bpf_filter
        self.paused     = False
        self._theme_idx = 0

        self.stats: dict[str, int] = defaultdict(int)
        self._alert_seen: dict[str, int]   = defaultdict(int)
        self._syn_ports:  dict[str, set]   = defaultdict(set)
        self._rst_count:  dict[str, int]   = defaultdict(int)
        self._icmp_count: dict[str, int]   = defaultdict(int)
        self._ip_count:   dict[str, int]   = defaultdict(int)
        self._arp_table:  dict[str, set]   = defaultdict(set)
        self._dns_times:  dict[str, deque] = defaultdict(deque)
        self._known_lan:  set[str]         = set()
        self._half_open:  dict[tuple, float] = {}

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
        self.set_interval(5.0, self._check_half_open)

    def _sniff_thread(self) -> None:
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=lambda pkt: self.call_from_thread(self._on_packet, pkt),
            store=False,
        )

    def _on_packet(self, pkt) -> None:
        if self.paused:
            return

        if ARP in pkt:
            self._handle_arp(pkt)
            return

        if IP not in pkt:
            return

        self.stats["Total"] += 1
        src = pkt[IP].src
        dst = pkt[IP].dst
        ts  = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        log = self.query_one("#pkt-log", RichLog)

        self._ip_count[src] += 1
        self._ip_count[dst] += 1

        if self._is_lan(src) and src not in self._known_lan:
            self._known_lan.add(src)
            self._alert("LOW", f"New LAN Host: {src}", src)

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
                    (f"{src}:{sp} -> {dst}:{dp}", "white"),
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
                    (f"{src}:{sp} -> {dst}:{dp}  status={code}", "white"),
                ))
                return

            if (sp == 443 or dp == 443) and Raw in pkt:
                sni = self._extract_sni(bytes(pkt[Raw].load))
                if sni:
                    self.stats["TLS"] += 1
                    log.write(Text.assemble(
                        ("TLS       ", "bold blue"),
                        (f"{ts}  ", "dim white"),
                        (f"{src}:{sp} -> {dst}:{dp}  ", "white"),
                        ("SNI: ", "dim white"),
                        (sni, "bold blue"),
                    ))
                    return

            for port, name, sev in ((23, "Telnet", "CRITICAL"), (21, "FTP", "HIGH")):
                if sp == port or dp == port:
                    self._alert(sev, f"{name} (cleartext)", f"{src}:{sp} -> {dst}:{dp}")

            if "S" in flags and "A" not in flags:
                # SYN — track for port scan and half-open detection
                self._syn_ports[src].add(dp)
                n = len(self._syn_ports[src])
                if n in (15, 50, 100):
                    self._alert("MEDIUM", "Port Scan", f"{src} SYN'd {n} distinct ports")
                self._half_open[(src, dst, sp, dp)] = time.monotonic()

            elif "S" in flags and "A" in flags:
                # SYN-ACK — server replied, connection completing
                self._half_open.pop((dst, src, dp, sp), None)

            if "R" in flags:
                self._rst_count[src] += 1
                c = self._rst_count[src]
                if c in (25, 100):
                    self._alert("LOW", "RST Flood / Scan", f"{src} sent {c} RST packets")
                self._half_open.pop((src, dst, sp, dp), None)
                self._half_open.pop((dst, src, dp, sp), None)

            if "F" in flags:
                self._half_open.pop((src, dst, sp, dp), None)
                self._half_open.pop((dst, src, dp, sp), None)

            row = Text.assemble(
                ("TCP       ", "bold cyan"),
                (f"{ts}  ", "dim white"),
                (f"{src}:{sp} -> {dst}:{dp}  ", "white"),
                (f"flags={flags}", "dim cyan"),
            )
            if Raw in pkt:
                snippet = pkt[Raw].load[:70].decode("utf-8", errors="ignore").replace("\n", " ").strip()
                if snippet:
                    row.append(f"\n          {snippet[:70]}", style="dim white")
            log.write(row)
            return

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
                        (f"{src} -> ", "white"),
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
                        (f"{name} -> {rdata}", "white"),
                    ))
                    return

            row = Text.assemble(
                ("UDP       ", "bold yellow"),
                (f"{ts}  ", "dim white"),
                (f"{src}:{sp} -> {dst}:{dp}", "white"),
            )
            if Raw in pkt:
                snippet = pkt[Raw].load[:70].decode("utf-8", errors="ignore").replace("\n", " ").strip()
                if snippet:
                    row.append(f"\n          {snippet[:70]}", style="dim white")
            log.write(row)
            return

        if ICMP in pkt:
            self.stats["ICMP"] += 1
            self._icmp_count[src] += 1
            kind = {
                0:  "Echo Reply",
                3:  "Dest Unreachable",
                4:  "Source Quench",
                5:  "Redirect",
                8:  "Echo Request",
                9:  "Router Advertisement",
                10: "Router Solicitation",
                11: "TTL Exceeded",
                12: "Parameter Problem",
                13: "Timestamp Request",
                14: "Timestamp Reply",
                17: "Address Mask Request",
                18: "Address Mask Reply",
            }.get(pkt[ICMP].type, f"type={pkt[ICMP].type}")
            log.write(Text.assemble(
                ("ICMP      ", "bold red"),
                (f"{ts}  ", "dim white"),
                (f"{src} -> {dst}  {kind}", "white"),
            ))
            c = self._icmp_count[src]
            if c in (30, 100):
                self._alert("MEDIUM", "ICMP Flood", f"{src} sent {c} ICMP packets")

    @staticmethod
    def _extract_sni(data: bytes) -> str | None:
        try:
            # TLS record: type 0x16 = handshake
            if len(data) < 6 or data[0] != 0x16:
                return None
            # Handshake type 0x01 = ClientHello
            if data[5] != 0x01:
                return None
            # Skip: record header (5) + handshake type (1) + length (3)
            #      + client version (2) + random (32) = offset 43
            pos = 43
            if len(data) <= pos:
                return None
            # session_id
            sid_len = data[pos]; pos += 1 + sid_len
            if len(data) < pos + 2:
                return None
            # cipher suites
            cs_len = int.from_bytes(data[pos:pos+2], "big"); pos += 2 + cs_len
            if len(data) < pos + 1:
                return None
            # compression methods
            cm_len = data[pos]; pos += 1 + cm_len
            if len(data) < pos + 2:
                return None
            # extensions
            ext_total = int.from_bytes(data[pos:pos+2], "big"); pos += 2
            end = pos + ext_total
            while pos + 4 <= end and pos + 4 <= len(data):
                ext_type = int.from_bytes(data[pos:pos+2], "big")
                ext_len  = int.from_bytes(data[pos+2:pos+4], "big")
                pos += 4
                if ext_type == 0x0000 and ext_len >= 5:  # SNI extension
                    name_len = int.from_bytes(data[pos+3:pos+5], "big")
                    return data[pos+5:pos+5+name_len].decode("ascii", errors="ignore")
                pos += ext_len
        except Exception:
            pass
        return None

    def _handle_arp(self, pkt) -> None:
        self.stats["ARP"] += 1
        arp = pkt[ARP]
        ts  = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        log = self.query_one("#pkt-log", RichLog)

        if arp.op == 1:  # who-has
            log.write(Text.assemble(
                ("ARP       ", "bold yellow"),
                (f"{ts}  ", "dim white"),
                ("who-has ", "white"),
                (arp.pdst, "cyan"),
                ("  tell ", "dim white"),
                (arp.psrc, "cyan"),
            ))
        elif arp.op == 2:  # is-at
            log.write(Text.assemble(
                ("ARP       ", "bold yellow"),
                (f"{ts}  ", "dim white"),
                (arp.psrc, "cyan"),
                (" is-at ", "white"),
                (arp.hwsrc, "green"),
            ))
            self._arp_table[arp.psrc].add(arp.hwsrc)
            if len(self._arp_table[arp.psrc]) > 1:
                macs = ", ".join(self._arp_table[arp.psrc])
                self._alert("CRITICAL", "ARP Spoofing",
                            f"{arp.psrc} claimed by: {macs}")

    @staticmethod
    def _is_lan(ip: str) -> bool:
        if ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                second = int(ip.split(".")[1])
                return 16 <= second <= 31
            except (IndexError, ValueError):
                pass
        return False

    def _check_half_open(self) -> None:
        now   = time.monotonic()
        stale = [flow for flow, t in self._half_open.items() if now - t > 5.0]
        if not stale:
            return
        per_src: dict[str, int] = defaultdict(int)
        for flow in stale:
            per_src[flow[0]] += 1
        for src_ip, count in per_src.items():
            if count >= 10:
                self._alert("HIGH", "SYN Without SYN-ACK",
                            f"{src_ip} has {count} half-open connections")
        for flow in stale:
            self._half_open.pop(flow, None)

    def _check_dns(self, src: str, name: str) -> None:
        BAD_KEYWORDS = {"track", "beacon", "telemetry", "c2", "cnc",
                        "botnet", "malware", "exfil", "keylog"}
        for kw in BAD_KEYWORDS:
            if kw in name.lower():
                self._alert("HIGH", "Suspicious DNS", f"{src} -> {name}")
                return
        if any(len(l) > 40 for l in name.split(".")):
            self._alert("MEDIUM", "Possible DNS Tunnel", f"{src} -> {name[:80]}")

        now = time.monotonic()
        dq  = self._dns_times[src]
        dq.append(now)
        while dq and dq[0] < now - 1.0:
            dq.popleft()
        rate = len(dq)
        if rate in (10, 20, 50):
            self._alert("HIGH", "DNS Exfil Rate", f"{src} sent {rate} DNS queries/sec")

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
        badge = f" x{n}" if n > 1 else ""

        msg = Text.assemble(
            (f" {severity} ", color),
            (f" {ts}{badge}\n", "dim white"),
            (f" {title}\n",     f"bold {color.split()[-1]}"),
            (f" {detail}\n",    "white"),
        )

        if n == 1 and title in ALERT_INFO:
            risk, fix = ALERT_INFO[title]
            msg.append("\n Risk  ", style="bold yellow")
            msg.append(risk + "\n", style="dim white")
            msg.append(" Fix   ", style="bold green")
            msg.append(fix + "\n", style="dim white")

        msg.append("-" * 40 + "\n", style="dim white")
        alog.write(msg)

    def _refresh_talkers(self) -> None:
        if not self._ip_count:
            return

        top = sorted(self._ip_count.items(), key=lambda x: -x[1])[:6]
        max_count = top[0][1] or 1
        bar_w = 10

        out = Text()
        for ip, count in top:
            filled = int((count / max_count) * bar_w)
            bar    = "#" * filled + "." * (bar_w - filled)
            owner  = _ip_owner(ip)
            out.append(f" {ip:<17}", style="white")
            out.append(bar, style="green")
            out.append(f"  {count:>5}  ", style="dim white")
            out.append(f"{owner}\n", style="cyan")

        self.query_one("#talkers", Static).update(out)

    def _refresh_stats(self) -> None:
        paused = "  [PAUSED]" if self.paused else ""
        parts  = "   ".join(f"{k}: {v}" for k, v in self.stats.items())
        self.query_one("#stats", Static).update(f"  {parts}{paused}")

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
