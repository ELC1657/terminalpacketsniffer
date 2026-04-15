#!/usr/bin/env python3

import argparse
import signal
import sys
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, ARP  # type: ignore[attr-defined]
    from scapy.layers.http import HTTPRequest, HTTPResponse  # type: ignore[attr-defined]
except ImportError:
    print("scapy not found - run: pip install scapy")
    sys.exit(1)

try:
    from scapy.layers.inet6 import IPv6  # type: ignore[attr-defined]
except ImportError:
    IPv6 = None


class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


stats        = defaultdict(int)
packet_count = 0
captured     = deque()   # replaced with bounded deque in main()
save_path    = None
_bytes_total = 0

# detection state
_syn_ports  = defaultdict(set)
_rst_count  = defaultdict(int)
_icmp_count = defaultdict(int)
_arp_table  = defaultdict(set)
_alert_seen = defaultdict(int)


ICMP_TYPES = {
    0:  "Echo Reply",           3:  "Dest Unreachable",
    4:  "Source Quench",        5:  "Redirect",
    8:  "Echo Request",         9:  "Router Advertisement",
    10: "Router Solicitation",  11: "TTL Exceeded",
    12: "Parameter Problem",    13: "Timestamp Request",
    14: "Timestamp Reply",      17: "Address Mask Request",
    18: "Address Mask Reply",
}


def extract_sni(data: bytes) -> str | None:
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


def _print_alert(sev: str, msg: str) -> None:
    key = f"{sev}|{msg[:60]}"
    _alert_seen[key] += 1
    n = _alert_seen[key]
    if n > 1 and n not in (5, 25, 100):
        return
    badge = f" x{n}" if n > 1 else ""
    colors = {
        "CRITICAL": C.RED + C.BOLD,
        "HIGH":     C.RED,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.CYAN,
    }
    color = colors.get(sev, C.WHITE)
    print(f"{color}[ALERT {sev}]{badge}{C.RESET}  {msg}")


def _detect(pkt) -> None:
    if ARP in pkt and pkt[ARP].op == 2:
        arp = pkt[ARP]
        _arp_table[arp.psrc].add(arp.hwsrc)
        if len(_arp_table[arp.psrc]) > 1:
            macs = ", ".join(_arp_table[arp.psrc])
            _print_alert("CRITICAL", f"ARP Spoofing: {arp.psrc} claimed by {macs}")
        return

    ip_layer = None
    if IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 is not None and IPv6 in pkt:
        ip_layer = pkt[IPv6]
    if ip_layer is None:
        return

    src = ip_layer.src
    dst = ip_layer.dst

    if TCP in pkt:
        sp, dp   = pkt[TCP].sport, pkt[TCP].dport
        flags    = str(pkt[TCP].flags)
        for port, name, sev in ((23, "Telnet (cleartext)", "CRITICAL"), (21, "FTP (cleartext)", "HIGH")):
            if sp == port or dp == port:
                _print_alert(sev, f"{name}  {src}:{sp} -> {dst}:{dp}")
        if "S" in flags and "A" not in flags:
            _syn_ports[src].add(dp)
            n = len(_syn_ports[src])
            if n in (15, 50, 100):
                _print_alert("MEDIUM", f"Port Scan: {src} SYN'd {n} distinct ports")
        if "R" in flags:
            _rst_count[src] += 1
            c = _rst_count[src]
            if c in (25, 100):
                _print_alert("LOW", f"RST Flood: {src} sent {c} RST packets")

    if ICMP in pkt:
        _icmp_count[src] += 1
        c = _icmp_count[src]
        if c in (30, 100):
            _print_alert("MEDIUM", f"ICMP Flood: {src} sent {c} ICMP packets")


def format_packet(packet) -> str | None:
    global packet_count, _bytes_total
    packet_count += 1
    _bytes_total += len(packet)
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if ARP in packet:
        stats["ARP"] += 1
        arp = packet[ARP]
        if arp.op == 1:
            return f"{C.YELLOW}[ARP]{C.RESET}       {ts}  who-has {arp.pdst}  tell {arp.psrc}"
        if arp.op == 2:
            return f"{C.YELLOW}[ARP]{C.RESET}       {ts}  {arp.psrc} is-at {arp.hwsrc}"
        return None

    ip_layer = None
    if IP in packet:
        ip_layer = packet[IP]
    elif IPv6 is not None and IPv6 in packet:
        ip_layer = packet[IPv6]

    if ip_layer is None:
        return None

    src = ip_layer.src
    dst = ip_layer.dst
    stats["IP"] += 1

    if TCP in packet:
        stats["TCP"] += 1
        sp, dp = packet[TCP].sport, packet[TCP].dport
        flags  = packet[TCP].flags

        if HTTPRequest in packet:
            stats["HTTP"] += 1
            method = packet[HTTPRequest].Method.decode(errors="ignore")
            host   = (packet[HTTPRequest].Host or b"").decode(errors="ignore") or dst
            path   = (packet[HTTPRequest].Path or b"/").decode(errors="ignore")
            return (
                f"{C.CYAN}[HTTP REQ]{C.RESET}  {ts}  {src}:{sp} -> {dst}:{dp}\n"
                f"  {C.GREEN}{method}{C.RESET} {host}{path}"
            )

        if HTTPResponse in packet:
            stats["HTTP"] += 1
            code = getattr(packet[HTTPResponse], "Status_Code", b"?")
            if isinstance(code, bytes):
                code = code.decode(errors="ignore")
            return (
                f"{C.CYAN}[HTTP RES]{C.RESET}  {ts}  {src}:{sp} -> {dst}:{dp}\n"
                f"  Status {C.GREEN}{code}{C.RESET}"
            )

        if (sp == 443 or dp == 443) and Raw in packet:
            sni = extract_sni(bytes(packet[Raw].load))
            if sni:
                stats["TLS"] += 1
                return f"{C.BLUE}[TLS]{C.RESET}       {ts}  {src}:{sp} -> {dst}:{dp}  SNI: {C.BOLD}{sni}{C.RESET}"

        line = f"{C.CYAN}[TCP]{C.RESET}       {ts}  {src}:{sp} -> {dst}:{dp}  flags={flags}"
        if Raw in packet:
            snippet = packet[Raw].load[:80].decode("utf-8", errors="ignore").replace("\n", " ").strip()
            if snippet:
                line += f"\n  Payload: {snippet}"
        return line

    if UDP in packet:
        stats["UDP"] += 1
        sp, dp = packet[UDP].sport, packet[UDP].dport

        if DNS in packet:
            stats["DNS"] += 1
            dns = packet[DNS]
            if dns.qr == 0 and DNSQR in packet:
                name = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                return f"{C.MAGENTA}[DNS QRY]{C.RESET}   {ts}  {src} -> {name}"
            if dns.qr == 1 and DNSRR in packet:
                name  = packet[DNSRR].rrname.decode(errors="ignore").rstrip(".")
                rdata = getattr(packet[DNSRR], "rdata", "?")
                return f"{C.MAGENTA}[DNS RPL]{C.RESET}   {ts}  {name} -> {rdata}"

        return f"{C.YELLOW}[UDP]{C.RESET}       {ts}  {src}:{sp} -> {dst}:{dp}"

    if ICMP in packet:
        stats["ICMP"] += 1
        kind = ICMP_TYPES.get(packet[ICMP].type, f"type={packet[ICMP].type}")
        return f"{C.RED}[ICMP]{C.RESET}      {ts}  {src} -> {dst}  {kind}"

    proto = getattr(ip_layer, "proto", getattr(ip_layer, "nh", "?"))
    return f"{C.WHITE}[IP/{proto}]{C.RESET}    {ts}  {src} -> {dst}"


def on_exit(*_) -> None:
    if save_path and captured:
        wrpcap(save_path, list(captured))
        print(f"\nSaved {len(captured)} packets to {C.BOLD}{save_path}{C.RESET}")

    b = _bytes_total
    bw_str = (
        f"{b/1_048_576:.1f} MB" if b >= 1_048_576 else
        f"{b/1024:.0f} KB"      if b >= 1024 else
        f"{b} B"
    )

    print(f"\n{C.BOLD}{'─'*42}")
    print("  Capture Statistics")
    print(f"{'─'*42}{C.RESET}")
    print(f"  {'Total':<14}: {packet_count}")
    print(f"  {'Bytes':<14}: {bw_str}")
    for proto, count in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {proto:<14}: {count}")
    print(f"{C.BOLD}{'─'*42}{C.RESET}")
    sys.exit(0)


def build_bpf(args) -> str | None:
    parts = []
    if args.protocol:
        mapping = {
            "tcp":  "tcp",
            "udp":  "udp",
            "icmp": "icmp",
            "dns":  "udp port 53",
            "http": "tcp port 80 or tcp port 8080",
        }
        parts.append(mapping[args.protocol])
    if args.port:
        parts.append(f"port {args.port}")
    if args.host:
        parts.append(f"host {args.host}")
    return " and ".join(parts) or None


def main():
    global save_path, captured

    ap = argparse.ArgumentParser(description="Packet Sniffer")
    ap.add_argument("-i", "--interface",                            help="Network interface (default: auto-select)")
    ap.add_argument("-p", "--protocol",
                    choices=["tcp", "udp", "icmp", "dns", "http"],  help="Filter by protocol")
    ap.add_argument(      "--host",                                 help="Filter by IP address or hostname")
    ap.add_argument(      "--port",    type=int,                    help="Filter by port number")
    ap.add_argument("-c", "--count",   type=int,   default=0,       help="Stop after N packets (0 = unlimited)")
    ap.add_argument("-w", "--write",   metavar="FILE",              help="Save capture to PCAP file")
    ap.add_argument("-r", "--read",    metavar="FILE",              help="Read from PCAP file instead of live capture")
    ap.add_argument(      "--buffer",  type=int,   default=10000,   help="Max packets held in memory for PCAP export (default: 10000)")
    ap.add_argument("-v", "--verbose", action="store_true",         help="Show raw Scapy layer dump")
    args = ap.parse_args()

    save_path  = args.write
    bpf_filter = build_bpf(args)
    captured   = deque(maxlen=args.buffer)

    print(f"\n{C.BOLD}Packet Sniffer{C.RESET}  (Ctrl+C to stop)\n")
    if args.interface: print(f"  Interface : {args.interface}")
    if args.read:      print(f"  Reading   : {args.read}")
    if bpf_filter:     print(f"  Filter    : {bpf_filter}")
    if args.count:     print(f"  Stop at   : {args.count} packets")
    if args.write:     print(f"  Save to   : {args.write}")
    print()

    signal.signal(signal.SIGINT, on_exit)

    def callback(pkt):
        _detect(pkt)
        if args.write:
            captured.append(pkt)
        if args.verbose:
            pkt.show()
            return
        out = format_packet(pkt)
        if out:
            print(out)

    if args.read:
        for pkt in rdpcap(args.read):
            callback(pkt)
        on_exit()
    else:
        sniff(
            iface=args.interface,
            filter=bpf_filter,
            prn=callback,
            count=args.count,
            store=False,
            promisc=False,
        )
        on_exit()


if __name__ == "__main__":
    main()
