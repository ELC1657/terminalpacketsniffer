#!/usr/bin/env python3

import argparse
import queue
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
    from textual.theme import Theme
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

MATRIX_THEME = Theme(
    name="matrix",
    primary="#00FF41",
    secondary="#008F11",
    accent="#00FF41",
    warning="#FFD700",
    error="#FF3131",
    success="#00FF41",
    background="#0D0D0D",
    surface="#111111",
    panel="#1A1A1A",
    dark=True,
)

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


MAX_PACKETS = 500


class SnifferApp(App):
    CSS = """
    Screen { layout: vertical; background: $surface; }

    #body {
        layout: horizontal;
        height: 1fr;
    }

    #left {
        width: 58%;
        layout: vertical;
    }

    #pkt-log {
        height: 2fr;
        border: round $primary;
        padding: 0 1;
        scrollbar-size-vertical: 1;
        scrollbar-color: $primary-darken-2;
        scrollbar-background: transparent;
    }

    #detail-pane {
        height: 1fr;
        border: round $accent;
        padding: 0 1;
        scrollbar-size-vertical: 1;
        scrollbar-color: $accent-darken-2;
        scrollbar-background: transparent;
    }

    #right {
        layout: vertical;
        width: 42%;
    }

    #alerts-pane {
        height: 2fr;
        border: round $error;
        padding: 0 1;
        scrollbar-size-vertical: 1;
        scrollbar-color: $error-darken-2;
        scrollbar-background: transparent;
    }

    #talkers-pane {
        height: 1fr;
        border: round $success;
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
        ("q", "quit",        "Quit"),
        ("c", "clear_all",   "Clear"),
        ("p", "pause",       "Pause"),
        ("t", "next_theme",  "Theme"),
        ("s", "cycle_speed", "Speed"),
        ("d",             "toggle_detail", "Detail"),
        ("left_square_bracket",  "prev_packet",   "◀ Prev"),
        ("right_square_bracket", "next_packet",   "Next ▶"),
    ]

    THEMES = [
        ("textual-dark",     "Default Dark"),
        ("nord",             "Nord"),
        ("gruvbox",          "Gruvbox"),
        ("catppuccin-mocha", "Catppuccin"),
        ("dracula",          "Dracula"),
        ("tokyo-night",      "Tokyo Night"),
        ("monokai",          "Monokai"),
        ("rose-pine",        "Rose Pine"),
        ("matrix",           "Matrix"),
    ]

    # (label, packets processed per 100 ms tick)
    SPEEDS = [
        ("Slow",   5),
        ("Normal", 50),
        ("Fast",   200),
    ]




    def __init__(self, interface=None, bpf_filter=None):
        super().__init__()
        self.interface  = interface
        self.bpf_filter = bpf_filter
        self.paused     = False
        self._theme_idx = 0
        self._speed_idx = 1  # default: Normal

        # detection state
        self.stats:       dict[str, int]   = defaultdict(int)
        self._alert_seen: dict[str, int]   = defaultdict(int)
        self._syn_ports:  dict[str, set]   = defaultdict(set)
        self._rst_count:  dict[str, int]   = defaultdict(int)
        self._icmp_count: dict[str, int]   = defaultdict(int)
        self._ip_count:   dict[str, int]   = defaultdict(int)
        self._arp_table:  dict[str, set]   = defaultdict(set)
        self._dns_times:  dict[str, deque] = defaultdict(deque)
        self._known_lan:  set[str]         = set()
        self._half_open:  dict[tuple, float] = {}

        # pipeline
        self._pkt_queue:    queue.Queue  = queue.Queue()
        self._pending:      list         = []   # (Text, pkt) staged this tick
        self._pkt_buf:      deque        = deque(maxlen=MAX_PACKETS)  # raw pkts for detail
        self._detail_frozen: bool        = False
        self._detail_idx:   int          = -1   # -1 = live (last), 0..n = browsing

        # cached widget refs — set in on_mount, never query_one in hot path
        self._w_pkt_log:   RichLog | None = None
        self._w_alert_log: RichLog | None = None
        self._w_detail:    RichLog | None = None
        self._w_talkers:   Static | None  = None
        self._w_stats:     Static | None  = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield RichLog(id="pkt-log", highlight=False, markup=False, wrap=False)
                with Vertical(id="detail-pane"):
                    yield RichLog(id="detail-log", highlight=False, markup=False, wrap=True)
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

        self._w_pkt_log   = self.query_one("#pkt-log",    RichLog)
        self._w_alert_log = self.query_one("#alert-log",  RichLog)
        self._w_detail    = self.query_one("#detail-log", RichLog)
        self._w_talkers   = self.query_one("#talkers",    Static)
        self._w_stats     = self.query_one("#stats",      Static)

        self._w_pkt_log.border_title                           = "  Live Packets"
        self.query_one("#detail-pane").border_title            = "  Packet Detail  [d] browse"
        self.query_one("#alerts-pane").border_title            = "  Security Alerts"
        self.query_one("#talkers-pane").border_title           = "  Top Talkers"

        self._w_detail.write(Text("Press [d] to browse packets  [ ] to step through", style="dim white"))

        self.register_theme(MATRIX_THEME)
        threading.Thread(target=self._sniff_thread, daemon=True).start()
        self.set_interval(0.1, self._drain_queue)
        self.set_interval(1.0, self._refresh_stats)
        self.set_interval(2.0, self._refresh_talkers)
        self.set_interval(5.0, self._check_half_open)

    # ── sniff / drain ──────────────────────────────────────────────────────

    def _sniff_thread(self) -> None:
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=lambda pkt: self._pkt_queue.put(pkt),
            store=False,
        )

    def _drain_queue(self) -> None:
        _, limit = self.SPEEDS[self._speed_idx]
        processed = 0
        while processed < limit:
            try:
                pkt = self._pkt_queue.get_nowait()
            except queue.Empty:
                break
            self._on_packet(pkt)
            processed += 1

        if self._pending:
            pkt_log = self._w_pkt_log
            for text, pkt in self._pending:
                self._pkt_buf.append((text, pkt))
                if not self._detail_frozen:
                    pkt_log.write(text)
            self._pending.clear()

    # ── packet handling ────────────────────────────────────────────────────

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

        self._ip_count[src] += 1
        self._ip_count[dst] += 1

        if self._is_lan(src) and src not in self._known_lan:
            self._known_lan.add(src)
            self._alert("LOW", f"New LAN Host: {src}", src)

        if TCP in pkt:
            self._handle_tcp(pkt, src, dst, ts)
            return

        if UDP in pkt:
            self._handle_udp(pkt, src, dst, ts)
            return

        if ICMP in pkt:
            self._handle_icmp(pkt, src, dst, ts)

    def _handle_tcp(self, pkt, src, dst, ts) -> None:
        self.stats["TCP"] += 1
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
        flags  = str(pkt[TCP].flags)

        if HTTPRequest in pkt:
            self.stats["HTTP"] += 1
            method = pkt[HTTPRequest].Method.decode(errors="ignore")
            host   = (pkt[HTTPRequest].Host or b"").decode(errors="ignore") or dst
            path   = (pkt[HTTPRequest].Path or b"/").decode(errors="ignore")
            self._stage(Text.assemble(
                ("HTTP REQ  ", "bold green"),
                (f"{ts}  ", "dim white"),
                (f"{src}:{sp} -> {dst}:{dp}", "white"),
                (f"\n          {method} {host}{path}", "green"),
            ), pkt)
            self._alert("HIGH", "Cleartext HTTP", f"{src}  {method} {host}{path}")
            return

        if HTTPResponse in pkt:
            self.stats["HTTP"] += 1
            code = getattr(pkt[HTTPResponse], "Status_Code", b"?")
            if isinstance(code, bytes):
                code = code.decode(errors="ignore")
            self._stage(Text.assemble(
                ("HTTP RES  ", "bold green"),
                (f"{ts}  ", "dim white"),
                (f"{src}:{sp} -> {dst}:{dp}  status={code}", "white"),
            ), pkt)
            return

        if (sp == 443 or dp == 443) and Raw in pkt:
            sni = self._extract_sni(bytes(pkt[Raw].load))
            if sni:
                self.stats["TLS"] += 1
                self._stage(Text.assemble(
                    ("TLS       ", "bold blue"),
                    (f"{ts}  ", "dim white"),
                    (f"{src}:{sp} -> {dst}:{dp}  ", "white"),
                    ("SNI: ", "dim white"),
                    (sni, "bold blue"),
                ), pkt)
                return

        for port, name, sev in ((23, "Telnet", "CRITICAL"), (21, "FTP", "HIGH")):
            if sp == port or dp == port:
                self._alert(sev, f"{name} (cleartext)", f"{src}:{sp} -> {dst}:{dp}")

        if "S" in flags and "A" not in flags:
            self._syn_ports[src].add(dp)
            n = len(self._syn_ports[src])
            if n in (15, 50, 100):
                self._alert("MEDIUM", "Port Scan", f"{src} SYN'd {n} distinct ports")
            self._half_open[(src, dst, sp, dp)] = time.monotonic()
        elif "S" in flags and "A" in flags:
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
            snippet = _safe_snippet(pkt[Raw].load)
            if snippet:
                row.append(f"\n          {snippet}", style="dim white")
        self._stage(row, pkt)

    def _handle_udp(self, pkt, src, dst, ts) -> None:
        self.stats["UDP"] += 1
        sp, dp = pkt[UDP].sport, pkt[UDP].dport

        if DNS in pkt:
            self.stats["DNS"] += 1
            dns = pkt[DNS]
            if dns.qr == 0 and DNSQR in pkt:
                name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                self._stage(Text.assemble(
                    ("DNS QRY   ", "bold magenta"),
                    (f"{ts}  ", "dim white"),
                    (f"{src} -> ", "white"),
                    (name, "magenta"),
                ), pkt)
                self._check_dns(src, name)
                return
            if dns.qr == 1 and DNSRR in pkt:
                name  = pkt[DNSRR].rrname.decode(errors="ignore").rstrip(".")
                rdata = getattr(pkt[DNSRR], "rdata", "?")
                self._stage(Text.assemble(
                    ("DNS RPL   ", "bold magenta"),
                    (f"{ts}  ", "dim white"),
                    (f"{name} -> {rdata}", "white"),
                ), pkt)
                return

        row = Text.assemble(
            ("UDP       ", "bold yellow"),
            (f"{ts}  ", "dim white"),
            (f"{src}:{sp} -> {dst}:{dp}", "white"),
        )
        if Raw in pkt:
            snippet = _safe_snippet(pkt[Raw].load)
            if snippet:
                row.append(f"\n          {snippet}", style="dim white")
        self._stage(row, pkt)

    def _handle_icmp(self, pkt, src, dst, ts) -> None:
        self.stats["ICMP"] += 1
        self._icmp_count[src] += 1
        kind = {
            0:  "Echo Reply",        3:  "Dest Unreachable",
            4:  "Source Quench",     5:  "Redirect",
            8:  "Echo Request",      9:  "Router Advertisement",
            10: "Router Solicitation", 11: "TTL Exceeded",
            12: "Parameter Problem", 13: "Timestamp Request",
            14: "Timestamp Reply",   17: "Address Mask Request",
            18: "Address Mask Reply",
        }.get(pkt[ICMP].type, f"type={pkt[ICMP].type}")
        self._stage(Text.assemble(
            ("ICMP      ", "bold red"),
            (f"{ts}  ", "dim white"),
            (f"{src} -> {dst}  {kind}", "white"),
        ), pkt)
        c = self._icmp_count[src]
        if c in (30, 100):
            self._alert("MEDIUM", "ICMP Flood", f"{src} sent {c} ICMP packets")

    def _handle_arp(self, pkt) -> None:
        self.stats["ARP"] += 1
        arp = pkt[ARP]
        ts  = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if arp.op == 1:
            self._stage(Text.assemble(
                ("ARP       ", "bold yellow"),
                (f"{ts}  ", "dim white"),
                ("who-has ", "white"),
                (arp.pdst, "cyan"),
                ("  tell ", "dim white"),
                (arp.psrc, "cyan"),
            ), pkt)
        elif arp.op == 2:
            self._stage(Text.assemble(
                ("ARP       ", "bold yellow"),
                (f"{ts}  ", "dim white"),
                (arp.psrc, "cyan"),
                (" is-at ", "white"),
                (arp.hwsrc, "green"),
            ), pkt)
            self._arp_table[arp.psrc].add(arp.hwsrc)
            if len(self._arp_table[arp.psrc]) > 1:
                macs = ", ".join(self._arp_table[arp.psrc])
                self._alert("CRITICAL", "ARP Spoofing", f"{arp.psrc} claimed by: {macs}")

    def _stage(self, text: Text, pkt) -> None:
        self._pending.append((text, pkt))

    # ── detection helpers ──────────────────────────────────────────────────

    @staticmethod
    def _extract_sni(data: bytes) -> str | None:
        try:
            if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
                return None
            pos = 43
            if len(data) <= pos:
                return None
            sid_len = data[pos]; pos += 1 + sid_len
            if len(data) < pos + 2: return None
            cs_len = int.from_bytes(data[pos:pos+2], "big"); pos += 2 + cs_len
            if len(data) < pos + 1: return None
            cm_len = data[pos]; pos += 1 + cm_len
            if len(data) < pos + 2: return None
            ext_total = int.from_bytes(data[pos:pos+2], "big"); pos += 2
            end = pos + ext_total
            while pos + 4 <= end and pos + 4 <= len(data):
                ext_type = int.from_bytes(data[pos:pos+2], "big")
                ext_len  = int.from_bytes(data[pos+2:pos+4], "big")
                pos += 4
                if ext_type == 0x0000 and ext_len >= 5:
                    name_len = int.from_bytes(data[pos+3:pos+5], "big")
                    return data[pos+5:pos+5+name_len].decode("ascii", errors="ignore")
                pos += ext_len
        except Exception:
            pass
        return None

    @staticmethod
    def _is_lan(ip: str) -> bool:
        if ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                return 16 <= int(ip.split(".")[1]) <= 31
            except (IndexError, ValueError):
                pass
        return False

    def _check_half_open(self) -> None:
        now   = time.monotonic()
        stale = [f for f, t in self._half_open.items() if now - t > 5.0]
        if not stale:
            return
        per_src: dict[str, int] = defaultdict(int)
        for f in stale:
            per_src[f[0]] += 1
        for src_ip, count in per_src.items():
            if count >= 10:
                self._alert("HIGH", "SYN Without SYN-ACK",
                            f"{src_ip} has {count} half-open connections")
        for f in stale:
            self._half_open.pop(f, None)

    def _check_dns(self, src: str, name: str) -> None:
        BAD = {"track", "beacon", "telemetry", "c2", "cnc", "botnet", "malware", "exfil", "keylog"}
        for kw in BAD:
            if kw in name.lower():
                self._alert("HIGH", "Suspicious DNS", f"{src} -> {name}")
                return
        if any(len(lbl) > 40 for lbl in name.split(".")):
            self._alert("MEDIUM", "Possible DNS Tunnel", f"{src} -> {name[:80]}")

        now = time.monotonic()
        dq  = self._dns_times[src]
        dq.append(now)
        while dq and dq[0] < now - 1.0:
            dq.popleft()
        if len(dq) in (10, 20, 50):
            self._alert("HIGH", "DNS Exfil Rate", f"{src} sent {len(dq)} DNS queries/sec")

    def _alert(self, severity: str, title: str, detail: str) -> None:
        key = f"{severity}|{title}"
        self._alert_seen[key] += 1
        n = self._alert_seen[key]
        if n > 1 and n not in (5, 25, 100):
            return

        self.stats["Alerts"] += 1
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
        self._w_alert_log.write(msg)

    # ── UI refresh ─────────────────────────────────────────────────────────

    def _refresh_talkers(self) -> None:
        if not self._ip_count:
            return
        top      = sorted(self._ip_count.items(), key=lambda x: -x[1])[:6]
        max_cnt  = top[0][1] or 1
        bar_w    = 10
        out      = Text()
        for ip, count in top:
            filled = int((count / max_cnt) * bar_w)
            bar    = "#" * filled + "." * (bar_w - filled)
            out.append(f" {ip:<17}", style="white")
            out.append(bar, style="green")
            out.append(f"  {count:>5}  ", style="dim white")
            out.append(f"{_ip_owner(ip)}\n", style="cyan")
        self._w_talkers.update(out)

    def _refresh_stats(self) -> None:
        speed_label, _ = self.SPEEDS[self._speed_idx]
        n       = len(self._pkt_buf)
        browse  = f"  [PKT {self._detail_idx + 1}/{n}]" if self._detail_frozen and n else ""
        paused  = "  [PAUSED]" if self.paused else ""
        parts   = "   ".join(f"{k}: {v}" for k, v in self.stats.items())
        self._w_stats.update(f"  {parts}   Speed: {speed_label}{paused}{browse}")

    def _show_detail(self) -> None:
        if not self._pkt_buf:
            return
        buf  = list(self._pkt_buf)
        n    = len(buf)
        idx  = self._detail_idx % n

        # ── redraw packet log as windowed view ──
        CONTEXT = 10
        win_start = max(0, idx - CONTEXT)
        win_end   = min(n, idx + CONTEXT + 1)

        pkt_log = self._w_pkt_log
        pkt_log.clear()

        if win_start > 0:
            pkt_log.write(Text(f"  ↑ {win_start} earlier packets", style="dim white"))

        tv  = self.theme_variables
        bg  = tv.get("primary", "blue")
        sep = Text("  " + "─" * 56, style=f"bold {bg}")

        for i in range(win_start, win_end):
            text, _ = buf[i]
            if i == idx:
                pkt_log.write(sep)
                row = Text(style=f"on {bg}")   # full-row bg in theme primary
                row.append("►  ", style="bold white")
                row.append_text(text)
                pkt_log.write(row)
                pkt_log.write(sep)
            else:
                pkt_log.write(text)

        if win_end < n:
            pkt_log.write(Text(f"  ↓ {n - win_end} later packets", style="dim white"))

        pkt_log.scroll_end(animate=False)

        # ── detail pane dump ──
        _, pkt = buf[idx]
        self._w_detail.clear()
        try:
            self._w_detail.write(pkt.show(dump=True))
        except Exception:
            self._w_detail.write("Could not parse packet layers.")

        self.query_one("#detail-pane").border_title = (
            f"  Packet Detail  [{idx + 1}/{n}]  [ prev  ] next  d exit"
        )

    # ── actions ────────────────────────────────────────────────────────────

    def action_clear_all(self) -> None:
        self._w_pkt_log.clear()
        self._w_alert_log.clear()
        self._w_detail.clear()
        self._pkt_buf.clear()
        self._pending.clear()
        self._detail_frozen = False
        self._detail_idx    = -1
        self._w_detail.write(Text("Press [d] to browse packets  [ ] to step through", style="dim white"))
        self.query_one("#detail-pane").border_title = "  Packet Detail  [d] browse"

    def action_pause(self) -> None:
        self.paused = not self.paused

    def action_next_theme(self) -> None:
        self._theme_idx = (self._theme_idx + 1) % len(self.THEMES)
        name, label = self.THEMES[self._theme_idx]
        self.theme = name
        self.notify(f"Theme: {label}", timeout=2)

    def action_cycle_speed(self) -> None:
        self._speed_idx = (self._speed_idx + 1) % len(self.SPEEDS)
        label, _ = self.SPEEDS[self._speed_idx]
        self.notify(f"Speed: {label}", timeout=2)

    def action_toggle_detail(self) -> None:
        if self._detail_frozen:
            self._detail_frozen = False
            self._detail_idx    = -1
            # replay buffered packets back into the live log
            pkt_log = self._w_pkt_log
            pkt_log.clear()
            for text, _ in self._pkt_buf:
                pkt_log.write(text)
            pkt_log.scroll_end(animate=False)
            self._w_detail.clear()
            self._w_detail.write(Text("Press [d] to browse packets  [ ] to step through", style="dim white"))
            self.query_one("#detail-pane").border_title = "  Packet Detail  [d] browse"
        else:
            if not self._pkt_buf:
                return
            self._detail_frozen = True
            self._detail_idx    = len(self._pkt_buf) - 1
            self._show_detail()

    def action_prev_packet(self) -> None:
        if not self._detail_frozen or not self._pkt_buf:
            return
        self._detail_idx = (self._detail_idx - 1) % len(self._pkt_buf)
        self._show_detail()

    def action_next_packet(self) -> None:
        if not self._detail_frozen or not self._pkt_buf:
            return
        self._detail_idx = (self._detail_idx + 1) % len(self._pkt_buf)
        self._show_detail()


# ── helpers (module-level, no self) ───────────────────────────────────────

def _safe_snippet(data: bytes, length: int = 70) -> str:
    raw = data[:length].decode("utf-8", errors="ignore")
    return "".join(c for c in raw if c.isprintable()).strip()


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
