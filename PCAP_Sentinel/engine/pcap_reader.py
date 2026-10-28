"""PCAP reader: decode captured network frames into packet dictionaries."""

from __future__ import annotations

import ipaddress
import struct
from typing import List, Tuple

from engine.default_rules.capture_files import (
    CaptureReader,
    PcapFormatError,
    LINK_TYPE_NAMES,
)

MAX_PACKETS = 250_000

TCP_FLAG_LETTERS = (
    ("F", 0x01),
    ("S", 0x02),
    ("R", 0x04),
    ("P", 0x08),
    ("A", 0x10),
    ("U", 0x20),
    ("E", 0x40),
    ("C", 0x80),
)


def blank_packet(number: int, timestamp, captured: int,
                 original, link_name: str) -> dict:
    """Create a packet dictionary with all expected fields."""

    return {
        "packet_number": number,
        "timestamp": timestamp,
        "captured_length": captured,
        "original_length": original,
        "link_type": link_name,
        "ip_version": None,
        "source_ip": None,
        "destination_ip": None,
        "ttl": None,
        "ip_protocol": None,
        "protocol": "OTHER",
        "source_port": None,
        "destination_port": None,
        "tcp_flags": None,
        "tcp_seq": None,
        "tcp_ack": None,
        "tcp_window": None,
        "icmp_type": None,
        "icmp_code": None,
        "payload": b"",
        "payload_length": None,
        "fragment": False,
        "truncated": False,
        "malformed": False,
        "note": None,
    }


def parse_frame(frame: dict) -> dict:
    """Decode one captured network frame without crashing on bad packets."""

    data = frame.get("data", b"")
    number = frame.get("number", 0)
    timestamp = frame.get("timestamp")
    original = frame.get("original_length")
    link_type = frame.get("link_type")

    link_name = LINK_TYPE_NAMES.get(
        link_type, f"Unsupported ({link_type})"
    )

    packet = blank_packet(
        number, timestamp, len(data), original, link_name
    )

    if original is not None and original > len(data):
        packet["truncated"] = True
        packet["note"] = "Capture contains a truncated packet"

    try:
        # Determine where the network-layer header starts.
        offset = 0

        # Ethernet link type.
        if link_type == 1:
            if len(data) < 14:
                raise ValueError("Incomplete Ethernet header")

            ether_type = struct.unpack_from("!H", data, 12)[0]
            offset = 14

            # Handle one or more VLAN tags.
            while ether_type in (0x8100, 0x88A8, 0x9100):
                if len(data) < offset + 4:
                    raise ValueError("Incomplete VLAN header")

                ether_type = struct.unpack_from(
                    "!H", data, offset + 2
                )[0]
                offset += 4

            if ether_type == 0x0800:
                network_type = "IPv4"
            elif ether_type == 0x86DD:
                network_type = "IPv6"
            elif ether_type == 0x0806:
                network_type = "ARP"
            else:
                packet["note"] = "Unsupported Ethernet protocol"
                return packet

        # Raw IPv4 / IPv6 link types.
        elif link_type in (101, 12, 228, 229):
            if not data:
                raise ValueError("Empty raw IP packet")

            version = data[0] >> 4

            if version == 4:
                network_type = "IPv4"
            elif version == 6:
                network_type = "IPv6"
            else:
                raise ValueError("Unknown raw IP version")

        else:
            packet["note"] = f"Unsupported link type: {link_type}"
            return packet

        # ---------------------------------------------------------
        # ARP
        # ---------------------------------------------------------
        if network_type == "ARP":
            if len(data) < offset + 8:
                raise ValueError("Incomplete ARP header")

            hardware_type, protocol_type, hlen, plen, operation = (
                struct.unpack_from("!HHBBH", data, offset)
            )

            arp_length = 8 + (2 * hlen) + (2 * plen)

            if len(data) < offset + arp_length:
                raise ValueError("Incomplete ARP addresses")

            if protocol_type == 0x0800 and plen == 4:
                sender_start = offset + 8 + hlen
                target_start = offset + 8 + hlen + plen + hlen

                packet["protocol"] = "ARP"
                packet["source_ip"] = str(
                    ipaddress.ip_address(
                        data[sender_start:sender_start + 4]
                    )
                )
                packet["destination_ip"] = str(
                    ipaddress.ip_address(
                        data[target_start:target_start + 4]
                    )
                )

            else:
                packet["protocol"] = "ARP"
                packet["note"] = "ARP address format not decoded"

            return packet

        # ---------------------------------------------------------
        # IPv4
        # ---------------------------------------------------------
        if network_type == "IPv4":
            if len(data) < offset + 20:
                raise ValueError("Incomplete IPv4 header")

            first_byte = data[offset]
            version = first_byte >> 4
            header_length = (first_byte & 0x0F) * 4

            if version != 4 or header_length < 20:
                raise ValueError("Invalid IPv4 header")

            if len(data) < offset + header_length:
                raise ValueError("Incomplete IPv4 options")

            total_length = struct.unpack_from(
                "!H", data, offset + 2
            )[0]

            if total_length < header_length:
                raise ValueError("Invalid IPv4 total length")

            ttl = data[offset + 8]
            protocol_number = data[offset + 9]

            source_ip = str(
                ipaddress.ip_address(data[offset + 12:offset + 16])
            )
            destination_ip = str(
                ipaddress.ip_address(data[offset + 16:offset + 20])
            )

            fragment_field = struct.unpack_from(
                "!H", data, offset + 6
            )[0]

            fragment_offset = fragment_field & 0x1FFF

            packet.update({
                "ip_version": 4,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "ttl": ttl,
                "ip_protocol": protocol_number,
            })

            transport_offset = offset + header_length
            declared_end = offset + total_length
            available_end = min(len(data), declared_end)

            if declared_end > len(data):
                packet["truncated"] = True
                packet["note"] = "IPv4 packet is shorter than declared"

            # A non-first fragment does not contain the transport header.
            if fragment_offset != 0:
                packet["fragment"] = True
                packet["note"] = "Non-first IPv4 fragment"
                return packet

            transport_end = available_end

        # ---------------------------------------------------------
        # IPv6
        # ---------------------------------------------------------
        else:
            if len(data) < offset + 40:
                raise ValueError("Incomplete IPv6 header")

            version = data[offset] >> 4

            if version != 6:
                raise ValueError("Invalid IPv6 version")

            payload_length = struct.unpack_from(
                "!H", data, offset + 4
            )[0]

            next_header = data[offset + 6]
            hop_limit = data[offset + 7]

            source_ip = str(
                ipaddress.ip_address(data[offset + 8:offset + 24])
            )
            destination_ip = str(
                ipaddress.ip_address(data[offset + 24:offset + 40])
            )

            packet.update({
                "ip_version": 6,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "ttl": hop_limit,
            })

            transport_offset = offset + 40
            declared_end = transport_offset + payload_length
            available_end = min(len(data), declared_end)

            if declared_end > len(data):
                packet["truncated"] = True
                packet["note"] = "IPv6 packet is shorter than declared"

            transport_end = available_end

            # Skip common IPv6 extension headers.
            extension_headers = {0, 43, 60, 135, 139, 140}

            while next_header in extension_headers:
                if transport_offset + 2 > transport_end:
                    raise ValueError("Incomplete IPv6 extension header")

                following_header = data[transport_offset]
                extension_length = (
                    data[transport_offset + 1] + 1
                ) * 8

                if transport_offset + extension_length > transport_end:
                    raise ValueError("Invalid IPv6 extension length")

                next_header = following_header
                transport_offset += extension_length

            # IPv6 fragment header.
            if next_header == 44:
                if transport_offset + 8 > transport_end:
                    raise ValueError("Incomplete IPv6 fragment header")

                following_header = data[transport_offset]
                fragment_field = struct.unpack_from(
                    "!H", data, transport_offset + 2
                )[0]

                fragment_offset = (fragment_field >> 3) & 0x1FFF

                if fragment_offset != 0:
                    packet["fragment"] = True
                    packet["note"] = "Non-first IPv6 fragment"
                    packet["ip_protocol"] = following_header
                    return packet

                next_header = following_header
                transport_offset += 8

            # IPv6 Authentication Header.
            if next_header == 51:
                if transport_offset + 2 > transport_end:
                    raise ValueError("Incomplete IPv6 AH header")

                following_header = data[transport_offset]
                ah_length = (data[transport_offset + 1] + 2) * 4

                if transport_offset + ah_length > transport_end:
                    raise ValueError("Invalid IPv6 AH length")

                next_header = following_header
                transport_offset += ah_length

            # ESP is encrypted and cannot be decoded here.
            if next_header == 50:
                packet["ip_protocol"] = 50
                packet["note"] = "IPv6 ESP payload is encrypted"
                return packet

            protocol_number = next_header
            packet["ip_protocol"] = protocol_number

        # ---------------------------------------------------------
        # TCP
        # ---------------------------------------------------------
        if protocol_number == 6:
            packet["protocol"] = "TCP"

            if transport_offset + 20 > transport_end:
                if not packet["truncated"]:
                    raise ValueError("Incomplete TCP header")

                packet["note"] = "Truncated TCP header"
                return packet

            source_port, destination_port, seq, ack = (
                struct.unpack_from("!HHII", data, transport_offset)
            )

            data_offset = data[transport_offset + 12] >> 4
            tcp_header_length = data_offset * 4

            if tcp_header_length < 20:
                raise ValueError("Invalid TCP header length")

            if transport_offset + tcp_header_length > transport_end:
                packet["truncated"] = True
                packet["note"] = "Incomplete TCP options"
                return packet

            flags_byte = data[transport_offset + 13]

            flags = "".join(
                letter for letter, bit in TCP_FLAG_LETTERS
                if flags_byte & bit
            )

            window = struct.unpack_from(
                "!H", data, transport_offset + 14
            )[0]

            payload_start = transport_offset + tcp_header_length
            payload = data[payload_start:transport_end]

            packet.update({
                "source_port": source_port,
                "destination_port": destination_port,
                "tcp_seq": seq,
                "tcp_ack": ack,
                "tcp_window": window,
                "tcp_flags": flags,
                "payload": payload,
                "payload_length": max(
                    0,
                    declared_end - payload_start
                ),
            })

        # ---------------------------------------------------------
        # UDP
        # ---------------------------------------------------------
        elif protocol_number == 17:
            packet["protocol"] = "UDP"

            if transport_offset + 8 > transport_end:
                if not packet["truncated"]:
                    raise ValueError("Incomplete UDP header")

                packet["note"] = "Truncated UDP header"
                return packet

            source_port, destination_port, udp_length = (
                struct.unpack_from("!HHH", data, transport_offset)
            )

            if udp_length < 8:
                raise ValueError("Invalid UDP length")

            udp_end = min(
                transport_end,
                transport_offset + udp_length
            )

            payload_start = transport_offset + 8
            payload = data[payload_start:udp_end]

            packet.update({
                "source_port": source_port,
                "destination_port": destination_port,
                "payload": payload,
                "payload_length": udp_length - 8,
            })

            if transport_offset + udp_length > declared_end:
                packet["note"] = "UDP length exceeds IP packet length"

        # ---------------------------------------------------------
        # ICMP and ICMPv6
        # ---------------------------------------------------------
        elif protocol_number in (1, 58):
            packet["protocol"] = (
                "ICMP" if protocol_number == 1 else "ICMPv6"
            )

            if transport_offset + 4 > transport_end:
                if not packet["truncated"]:
                    raise ValueError("Incomplete ICMP header")

                packet["note"] = "Truncated ICMP header"
                return packet

            packet["icmp_type"] = data[transport_offset]
            packet["icmp_code"] = data[transport_offset + 1]

            # ICMP messages normally have an 8-byte header.
            payload_start = min(transport_offset + 8, transport_end)

            packet["payload"] = data[payload_start:transport_end]
            packet["payload_length"] = max(
                0, declared_end - payload_start
            )

        else:
            packet["protocol"] = "OTHER"
            packet["note"] = f"Unsupported IP protocol: {protocol_number}"

        return packet

    except (struct.error, IndexError, ValueError, TypeError) as error:
        packet["malformed"] = True
        packet["note"] = str(error)
        return packet


def read_pcap(
    file_path: str,
    max_packets: int = MAX_PACKETS
) -> Tuple[List[dict], dict]:
    """Read a PCAP or PCAPNG file and return packets and capture metadata."""

    if max_packets < 0:
        raise ValueError("max_packets must be zero or greater")

    reader = CaptureReader(file_path)

    packets = []
    warnings = list(reader.warnings)
    read_limit_reached = False

    for frame in reader.frames():
        if len(packets) >= max_packets:
            read_limit_reached = True
            break

        packets.append(parse_frame(frame))

    if read_limit_reached:
        warnings.append(
            f"Only the first {max_packets} packets were analysed"
        )

    capture_info = {
        "file_size_bytes": reader.file_size,
        "format": reader.format,
        "link_types": sorted(reader.link_types.values()),
        "snaplen": reader.snaplen,
        "packet_count": len(packets),
        "file_truncated": reader.file_truncated,
        "read_limit_reached": read_limit_reached,
        "warnings": warnings,
        "unsupported_packets": sum(
            1 for packet in packets
            if packet["note"]
            and "unsupported" in packet["note"].lower()
        ),
        "malformed_packets": sum(
            1 for packet in packets if packet["malformed"]
        ),
        "truncated_packets": sum(
            1 for packet in packets if packet["truncated"]
        ),
    }

    return packets, capture_info
