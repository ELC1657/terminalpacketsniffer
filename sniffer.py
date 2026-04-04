#!/usr/bin/env python3

import argparse
import signal
import sys
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("scapy not found - run: pip install scapy")
    sys.exit(1)


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
captured     = []
save_path    = None


def format_packet(packet) -> str | None:
    global packet_count
    packet_count += 1
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if IP not in packet:
        return None

    src = packet[IP].src
    dst = packet[IP].dst
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
        names = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
        kind  = names.get(packet[ICMP].type, f"type={packet[ICMP].type}")
        return f"{C.RED}[ICMP]{C.RESET}      {ts}  {src} -> {dst}  {kind}"

    return f"{C.WHITE}[IP/{packet[IP].proto}]{C.RESET}    {ts}  {src} -> {dst}"


def on_exit(sig=None, frame=None):
    if save_path and captured:
        wrpcap(save_path, captured)
        print(f"\nSaved {len(captured)} packets to {C.BOLD}{save_path}{C.RESET}")

    print(f"\n{C.BOLD}{'─'*42}")
    print("  Capture Statistics")
    print(f"{'─'*42}{C.RESET}")
    print(f"  {'Total':<14}: {packet_count}")
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
    global save_path

    ap = argparse.ArgumentParser(description="Packet Sniffer")
    ap.add_argument("-i", "--interface",                           help="Network interface (default: auto-select)")
    ap.add_argument("-p", "--protocol",
                    choices=["tcp", "udp", "icmp", "dns", "http"], help="Filter by protocol")
    ap.add_argument(      "--host",                                help="Filter by IP address or hostname")
    ap.add_argument(      "--port",    type=int,                   help="Filter by port number")
    ap.add_argument("-c", "--count",   type=int,   default=0,      help="Stop after N packets (0 = unlimited)")
    ap.add_argument("-w", "--write",   metavar="FILE",             help="Save capture to PCAP file")
    ap.add_argument("-v", "--verbose", action="store_true",        help="Show raw Scapy layer dump")
    args = ap.parse_args()

    save_path  = args.write
    bpf_filter = build_bpf(args)

    print(f"\n{C.BOLD}Packet Sniffer{C.RESET}  (Ctrl+C to stop)\n")
    if args.interface: print(f"  Interface : {args.interface}")
    if bpf_filter:     print(f"  Filter    : {bpf_filter}")
    if args.count:     print(f"  Stop at   : {args.count} packets")
    if args.write:     print(f"  Save to   : {args.write}")
    print()

    signal.signal(signal.SIGINT, on_exit)

    def callback(pkt):
        if args.write:
            captured.append(pkt)
        if args.verbose:
            pkt.show()
            return
        out = format_packet(pkt)
        if out:
            print(out)

    sniff(
        iface=args.interface,
        filter=bpf_filter,
        prn=callback,
        count=args.count,
        store=False,
    )

    on_exit()


if __name__ == "__main__":
    main()
