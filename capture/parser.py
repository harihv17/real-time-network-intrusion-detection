"""Packet parser translating raw or Scapy packet layers into standard PacketEvents.

Ensures strict privacy: only header metadata (IPs, ports, flags, size, timestamp)
is extracted. No user payload or packet bodies are stored or processed.
"""

import time
from typing import Optional
from simulator.models import PacketEvent, Protocol


def format_tcp_flags(flags_val) -> str:
    """Decodes TCP flag representation into standard comma-separated labels."""
    if not flags_val:
        return "NONE"

    # Handle Scapy FlagValue / int / str
    flag_str = str(flags_val).upper()
    flag_map = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
    }
    extracted = []
    for char in flag_str:
        if char in flag_map and flag_map[char] not in extracted:
            extracted.append(flag_map[char])

    return ", ".join(extracted) if extracted else flag_str


def parse_packet_metadata(pkt) -> Optional[PacketEvent]:
    """Extracts network layer metadata into a PacketEvent from a raw Scapy packet."""
    try:
        # Extract packet timestamp
        pkt_time = float(getattr(pkt, "time", time.time()))
        pkt_size = len(pkt)

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = 0
        dst_port = 0
        proto_str = "OTHER"
        tcp_flags = "NONE"

        # Check for IP Layer (IPv4 or IPv6)
        if pkt.haslayer("IP"):
            ip_layer = pkt["IP"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        elif pkt.haslayer("IPv6"):
            ip_layer = pkt["IPv6"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        elif pkt.haslayer("ARP"):
            arp_layer = pkt["ARP"]
            src_ip = getattr(arp_layer, "psrc", "0.0.0.0")
            dst_ip = getattr(arp_layer, "pdst", "0.0.0.0")
            proto_str = "ARP"
            return PacketEvent(
                timestamp=pkt_time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=0,
                dst_port=0,
                protocol="ARP",
                packet_size=pkt_size,
                tcp_flags="NONE",
                scenario="Live Network Traffic",
                is_malicious=False,
                attack_type=None,
            )
        else:
            # Non-IP layer packet
            return None

        # Check Transport Layer
        if pkt.haslayer("TCP"):
            tcp_layer = pkt["TCP"]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            proto_str = Protocol.TCP.value
            tcp_flags = format_tcp_flags(tcp_layer.flags)

        elif pkt.haslayer("UDP"):
            udp_layer = pkt["UDP"]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            proto_str = Protocol.UDP.value
            tcp_flags = "NONE"

        elif pkt.haslayer("ICMP"):
            proto_str = Protocol.ICMP.value
            src_port = 0
            dst_port = 0
            tcp_flags = "NONE"

        else:
            proto_str = "IP-OTHER"

        return PacketEvent(
            timestamp=pkt_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto_str,
            packet_size=pkt_size,
            tcp_flags=tcp_flags,
            scenario="Live Network Traffic",
            is_malicious=False,
            attack_type=None,
        )

    except Exception:
        # Ignore malformed or truncated packets safely
        return None
