
"""TASK 2 - Traffic analyser: statistics, conversations and traffic rates."""

from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from engine.default_rules.services import service_name

DEFAULT_CONFIG = {
    "top_n": 10,
    "rate_window_seconds": 1.0,
    "max_rate_bins": 3600,
    "burst_factor": 5.0,
    "burst_min_packets": 100,
    "max_flows": 50_000,
    "series_points": 120,
}


def _utc(timestamp: Optional[float]) -> Optional[str]:
    """Convert epoch seconds to ISO-8601 UTC text."""
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(
            float(timestamp), tz=timezone.utc
        ).isoformat()
    except (TypeError, OverflowError, OSError, ValueError):
        return None


def capture_block(packets: List[dict],
                  capture_info: Optional[dict]) -> dict:
    """Summarise the capture file and its timestamps."""
    info = capture_info or {}
    timestamps = []

    for packet in packets:
        timestamp = packet.get("timestamp")
        if timestamp is not None:
            try:
                timestamps.append(float(timestamp))
            except (TypeError, ValueError, OverflowError):
                continue

    first = min(timestamps) if timestamps else None
    last = max(timestamps) if timestamps else None
    duration = round(last - first, 6) if first is not None else None

    return {
        "file_size_bytes": info.get("file_size_bytes"),
        "format": info.get("format", "Unknown"),
        "link_types": list(info.get("link_types") or []),
        "packet_count": len(packets),
        "first_timestamp": first,
        "last_timestamp": last,
        "duration_seconds": duration,
        "start_utc": _utc(first),
        "end_utc": _utc(last),
    }


def totals_block(packets: List[dict]) -> dict:
    """Calculate total packet count and packet sizes."""
    count = len(packets)
    captured_bytes = sum(
        int(packet.get("captured_length") or 0)
        for packet in packets
    )

    if count == 0 or any(
        packet.get("original_length") is None for packet in packets
    ):
        wire_bytes = None
    else:
        wire_bytes = sum(
            int(packet["original_length"]) for packet in packets
        )

    average = round(captured_bytes / count, 1) if count else None

    return {
        "packets": count,
        "captured_bytes": captured_bytes,
        "wire_bytes": wire_bytes,
        "average_packet_size": average,
    }


def protocol_table(packets: List[dict]) -> List[dict]:
    """Count packets and captured bytes for each protocol."""
    counts = Counter()
    byte_counts = Counter()

    for packet in packets:
        protocol = packet.get("protocol") or "OTHER"
        counts[protocol] += 1
        byte_counts[protocol] += int(
            packet.get("captured_length") or 0
        )

    total = len(packets)
    rows = []

    for protocol, count in counts.most_common():
        rows.append({
            "protocol": protocol,
            "packets": count,
            "bytes": byte_counts[protocol],
            "percent": round(100 * count / total, 1) if total else 0.0,
        })

    return rows


def top_hosts(packets: List[dict], role: str,
              top_n: int) -> List[dict]:
    """Return the busiest source or destination IP addresses."""
    if role not in ("source", "destination"):
        raise ValueError("role must be 'source' or 'destination'")

    field = "source_ip" if role == "source" else "destination_ip"
    counts = Counter()
    byte_counts = Counter()

    for packet in packets:
        address = packet.get(field)
        if address is None:
            continue
        counts[address] += 1
        byte_counts[address] += int(
            packet.get("captured_length") or 0
        )

    return [
        {
            "ip": address,
            "packets": count,
            "bytes": byte_counts[address],
        }
        for address, count in counts.most_common(max(0, top_n))
    ]


def top_service_ports(packets: List[dict],
                      top_n: int) -> List[dict]:
    """Find the busiest likely server-side TCP/UDP ports."""
    counts = Counter()

    for packet in packets:
        protocol = packet.get("protocol")
        if protocol not in ("TCP", "UDP"):
            continue

        destination = packet.get("destination_port")
        source = packet.get("source_port")

        if destination is None:
            continue

        # Avoid counting replies travelling towards random client ports.
        if source is not None and destination > source:
            continue

        counts[(protocol, destination)] += 1

    rows = []
    for (protocol, port), count in counts.most_common(max(0, top_n)):
        try:
            service = service_name(port)
        except (TypeError, ValueError):
            service = None

        rows.append({
            "port": port,
            "protocol": protocol,
            "service": service,
            "packets": count,
        })

    return rows


def tcp_statistics(packets: List[dict]) -> dict:
    """Summarise TCP flags and estimate repeated segments."""
    tcp_packets = [
        packet for packet in packets
        if packet.get("protocol") == "TCP"
    ]

    attempts = 0
    synack = 0
    resets = 0
    fins = 0
    flag_counts = Counter()
    seen = set()
    retransmissions = 0
    max_seen = 1_000_000

    for packet in tcp_packets:
        flags = packet.get("tcp_flags") or ""

        has_syn = "S" in flags
        has_ack = "A" in flags
        has_rst = "R" in flags
        has_fin = "F" in flags

        if has_syn and not has_ack and not has_rst:
            attempts += 1
            flag_counts["SYN"] += 1

        if has_syn and has_ack:
            synack += 1
            flag_counts["SYN-ACK"] += 1

        if has_rst:
            resets += 1
            flag_counts["RST"] += 1

        if has_fin:
            fins += 1
            flag_counts["FIN"] += 1

        if "P" in flags:
            flag_counts["PSH"] += 1

        if has_ack and not has_syn:
            flag_counts["ACK"] += 1

        payload_length = packet.get("payload_length")
        try:
            payload_length = int(payload_length or 0)
        except (TypeError, ValueError):
            payload_length = 0

        # Only count data-bearing or SYN/FIN segments for this estimate.
        if not (payload_length > 0 or has_syn or has_fin):
            continue

        key = (
            packet.get("source_ip"),
            packet.get("source_port"),
            packet.get("destination_ip"),
            packet.get("destination_port"),
            packet.get("tcp_seq"),
            payload_length,
            has_syn,
            has_fin,
        )

        if key in seen:
            retransmissions += 1
        elif len(seen) < max_seen:
            seen.add(key)

    return {
        "packets": len(tcp_packets),
        "connection_attempts": attempts,
        "synack_responses": synack,
        "reset_packets": resets,
        "fin_packets": fins,
        "retransmissions": retransmissions,
        "flag_counts": dict(flag_counts),
    }


def build_flows(packets: List[dict],
                max_flows: int) -> Tuple[List[dict], int]:
    """Group packets into conversations in both directions."""
    flows = {}
    untracked = 0
    max_flows = max(0, int(max_flows))

    for packet in packets:
        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")
        protocol = packet.get("protocol") or "OTHER"

        if (
            source_ip is None
            or destination_ip is None
            or protocol == "ARP"
        ):
            continue

        source_port = packet.get("source_port")
        destination_port = packet.get("destination_port")

        # Treat a missing port as zero when building the flow key.
        source_endpoint = (source_ip, source_port or 0)
        destination_endpoint = (destination_ip, destination_port or 0)

        endpoints = tuple(sorted((
            source_endpoint, destination_endpoint
        )))
        key = (protocol, endpoints)

        if key not in flows:
            if len(flows) >= max_flows:
                untracked += 1
                continue

            flows[key] = {
                "protocol": protocol,
                "a_ip": source_ip,
                "a_port": source_port,
                "b_ip": destination_ip,
                "b_port": destination_port,
                "packets": 0,
                "bytes": 0,
                "packets_a_to_b": 0,
                "first_ts": None,
                "last_ts": None,
                "duration": None,
            }

        flow = flows[key]
        flow["packets"] += 1
        flow["bytes"] += int(packet.get("captured_length") or 0)

        # A is the endpoint that sent the first packet in this flow.
        if (
            source_ip == flow["a_ip"]
            and source_port == flow["a_port"]
        ):
            flow["packets_a_to_b"] += 1

        timestamp = packet.get("timestamp")
        if timestamp is not None:
            try:
                timestamp = float(timestamp)
                if flow["first_ts"] is None:
                    flow["first_ts"] = timestamp
                    flow["last_ts"] = timestamp
                else:
                    flow["first_ts"] = min(flow["first_ts"], timestamp)
                    flow["last_ts"] = max(flow["last_ts"], timestamp)
            except (TypeError, ValueError, OverflowError):
                pass

    result = list(flows.values())

    for flow in result:
        if flow["first_ts"] is not None:
            flow["duration"] = round(
                flow["last_ts"] - flow["first_ts"], 6
            )

    result.sort(key=lambda flow: flow["packets"], reverse=True)
    return result, untracked


def rate_summary(packets: List[dict],
                 config: dict) -> Optional[dict]:
    """Calculate packets-per-second rates and identify busy windows."""
    timed = []

    for packet in packets:
        timestamp = packet.get("timestamp")
        if timestamp is None:
            continue
        try:
            timed.append((
                float(timestamp),
                int(packet.get("captured_length") or 0),
            ))
        except (TypeError, ValueError, OverflowError):
            continue

    if not timed:
        return None

    first = min(timestamp for timestamp, _ in timed)
    last = max(timestamp for timestamp, _ in timed)
    duration = last - first

    width = max(
        float(config.get("rate_window_seconds", 1.0)), 0.001
    )
    max_bins = max(1, int(config.get("max_rate_bins", 3600)))

    if duration / width > max_bins:
        width = duration / max_bins

    bins = {}
    for timestamp, size in timed:
        index = int((timestamp - first) / width)
        bins.setdefault(index, {"packets": 0, "bytes": 0})
        bins[index]["packets"] += 1
        bins[index]["bytes"] += size

    if not bins:
        return None

    busiest_index = max(
        bins, key=lambda index: bins[index]["packets"]
    )
    busiest = bins[busiest_index]

    peak = {
        "offset_seconds": round(busiest_index * width, 3),
        "packets": busiest["packets"],
        "packets_per_second": round(busiest["packets"] / width, 3),
        "bytes": busiest["bytes"],
    }

    busy_values = [
        values["packets"] for values in bins.values()
        if values["packets"] > 0
    ]
    median_busy = statistics.median(busy_values) if busy_values else 0

    burst_factor = float(config.get("burst_factor", 5.0))
    burst_min = int(config.get("burst_min_packets", 100))

    bursts = []
    for index, values in bins.items():
        count = values["packets"]
        if count >= burst_min and count >= burst_factor * median_busy:
            bursts.append({
                "offset_seconds": round(index * width, 3),
                "window_seconds": round(width, 6),
                "packets": count,
                "packets_per_second": round(count / width, 3),
                "bytes": values["bytes"],
            })

    bursts.sort(key=lambda row: row["packets"], reverse=True)
    bursts = bursts[:5]

    average_pps = (
        round(len(timed) / duration, 3) if duration > 0 else None
    )
    total_bytes = sum(size for _, size in timed)
    average_bytes = (
        round(total_bytes / duration, 3) if duration > 0 else None
    )

    # Merge neighbouring windows into approximately series_points buckets.
    last_index = max(bins)
    number_of_bins = last_index + 1
    target_points = max(
        1, int(config.get("series_points", 120))
    )
    group_size = max(
        1, (number_of_bins + target_points - 1) // target_points
    )

    series = []
    for start_index in range(0, number_of_bins, group_size):
        end_index = min(number_of_bins, start_index + group_size)
        packet_count = 0
        byte_count = 0

        for index in range(start_index, end_index):
            values = bins.get(index, {"packets": 0, "bytes": 0})
            packet_count += values["packets"]
            byte_count += values["bytes"]

        series.append({
            "offset_seconds": round(start_index * width, 3),
            "packets": packet_count,
            "bytes": byte_count,
        })

    return {
        "window_seconds": round(width, 6),
        "average_pps": average_pps,
        "average_bytes_per_second": average_bytes,
        "peak": peak,
        "bursts": bursts,
        "series": series,
    }


def quality_block(packets: List[dict],
                  capture_info: Optional[dict]) -> dict:
    """Report capture problems and missing information."""
    info = capture_info or {}

    truncated = sum(bool(packet.get("truncated")) for packet in packets)
    malformed = sum(bool(packet.get("malformed")) for packet in packets)
    no_timestamp = sum(
        packet.get("timestamp") is None for packet in packets
    )

    unsupported = info.get("unsupported_packets")
    file_truncated = info.get("file_truncated", False)
    read_limit_reached = info.get("read_limit_reached", False)
    warnings = list(info.get("warnings") or [])
    notes = []

    if no_timestamp:
        notes.append(
            f"{no_timestamp} packet(s) have no timestamp; "
            "time-based statistics may be incomplete."
        )

    if truncated:
        notes.append(
            f"{truncated} packet(s) are truncated; some headers or payloads "
            "may be incomplete."
        )

    if malformed:
        notes.append(
            f"{malformed} malformed packet(s) were found."
        )

    if file_truncated:
        notes.append(
            "The capture file appears to end abruptly."
        )

    if read_limit_reached:
        notes.append(
            "The packet reading limit was reached; the analysis may not "
            "include the entire file."
        )

    if unsupported:
        notes.append(
            f"{unsupported} packet(s) use unsupported link types or formats."
        )

    return {
        "truncated_packets": truncated,
        "malformed_packets": malformed,
        "unsupported_packets": unsupported,
        "packets_without_timestamp": no_timestamp,
        "file_truncated": file_truncated,
        "read_limit_reached": read_limit_reached,
        "warnings": warnings,
        "notes": notes,
    }


def analyze_traffic(packets: List[dict],
                    capture_info: Optional[dict] = None,
                    config: Optional[dict] = None) -> dict:
    """Build the shared context used by detection rules and the dashboard."""
    config = {**DEFAULT_CONFIG, **(config or {})}

    flow_list, untracked = build_flows(
        packets, config["max_flows"]
    )

    summary = {
        "capture": capture_block(packets, capture_info),
        "totals": totals_block(packets),
        "protocols": protocol_table(packets),
        "top_sources": top_hosts(packets, "source", config["top_n"]),
        "top_destinations": top_hosts(
            packets, "destination", config["top_n"]
        ),
        "top_destination_ports": top_service_ports(
            packets, config["top_n"]
        ),
        "tcp": tcp_statistics(packets),
        "flows": {
            "total": len(flow_list),
            "tracked": len(flow_list),
            "untracked_packets": untracked,
            "truncated": untracked > 0,
            "top": flow_list[:config["top_n"]],
        },
        "traffic_rate": rate_summary(packets, config),
        "data_quality": quality_block(packets, capture_info),
    }

    return {
        "packets": packets,
        "capture_info": dict(capture_info or {}),
        "config": config,
        "flows": flow_list,
        "summary": summary,
    }
