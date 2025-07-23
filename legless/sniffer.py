#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dhcp6 import *
from datetime import datetime
from colorama import Fore, Style, init
import argparse

init(autoreset=True)

DHCP6_TYPES = {
    DHCP6_Solicit: "Solicit",
    DHCP6_Advertise: "Advertise",
    DHCP6_Request: "Request",
    DHCP6_Reply: "Reply",
    DHCP6_Renew: "Renew",
    DHCP6_Rebind: "Rebind",
    DHCP6_RelayForward: "Relay-Forward",
    DHCP6_RelayReply: "Relay-Reply"
}

ICMP6_TYPES = {
    ICMPv6ND_RS:         ("ICMPv6 - Router Solicitation", Fore.CYAN),
    ICMPv6ND_RA:         ("ICMPv6 - Router Advertisement", Fore.GREEN),
    ICMPv6ND_NS:         ("ICMPv6 - Neighbor Solicitation", Fore.BLUE),
    ICMPv6ND_NA:         ("ICMPv6 - Neighbor Advertisement", Fore.MAGENTA),
    ICMPv6ND_Redirect:   ("ICMPv6 - Redirect", Fore.LIGHTRED_EX),
    ICMPv6MLReport:      ("ICMPv6 - MLD Report", Fore.LIGHTCYAN_EX),
    ICMPv6MLReport2:     ("ICMPv6 - MLD Report", Fore.LIGHTCYAN_EX),
    ICMPv6MLDone:        ("ICMPv6 - MLD Done", Fore.LIGHTCYAN_EX),
    ICMPv6EchoRequest:   ("ICMPv6 - Echo Request", Fore.LIGHTBLACK_EX),
    ICMPv6EchoReply:     ("ICMPv6 - Echo Reply", Fore.LIGHTBLACK_EX)
}

def handle(pkt):
    eth_src = pkt[Ether].src if Ether in pkt else "?"
    eth_dst = pkt[Ether].dst if Ether in pkt else "?"
    ip6_src = pkt[IPv6].src if IPv6 in pkt else "?"
    ip6_dst = pkt[IPv6].dst if IPv6 in pkt else "?"

    # ICMPv6 Detection
    for proto, (desc, color) in ICMP6_TYPES.items():
        if proto in pkt:
            break
    else:
        # DHCPv6 Detection
        if UDP in pkt and pkt[UDP].dport == 547:
            for dhcp_type, name in DHCP6_TYPES.items():
                if dhcp_type in pkt:
                    desc = f"DHCPv6 - {name}"
                    color = Fore.YELLOW
                    break
            else:
                return
        else:
            return

    print(color + f"[{datetime.now().strftime('%H:%M:%S')}] {desc}")
    print(f"{Style.DIM}  MAC  {eth_src} -> {eth_dst}")
    print(f"{Style.DIM}  IPv6 {ip6_src} -> {ip6_dst}")
    print(Style.RESET_ALL + "-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IPv6 NDP & DHCPv6 Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Interface to sniff on")
    parser.add_argument("-t", "--time", type=int, default=0, help="Sniff duration (0 = infinite)")
    args = parser.parse_args()

    print(Fore.LIGHTWHITE_EX + f"[*] Sniffing on {args.interface} for {args.time or '∞'} seconds...\n")
    sniff(iface=args.interface, prn=handle, timeout=args.time or None, store=0)
