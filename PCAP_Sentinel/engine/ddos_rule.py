from collections import Counter
from typing import List

from engine.default_rules.base_rule import BaseRule


class DDoSDetectionRule(BaseRule):
    rule_id = "syn_flood"
    name = "TCP SYN Flood Detection"
    category = "Denial of Service"

    defaults = {
        "syn_threshold": 100,
        "window_seconds": 5,
        "completed_cutoff": 0.5,
    }

    def detect(self, context: dict) -> List[dict]:
        # Your existing detection code goes here.
        pass


def detect(self, context: dict) -> List[dict]:
    """Detect possible TCP SYN flood activity in captured network traffic."""

    packets = context.get("packets", [])

    syn_threshold = self.params["syn_threshold"]
    window_seconds = self.params["window_seconds"]
    completed_cutoff = self.params["completed_cutoff"]

    # TODO 1: Keep timestamped TCP packets and remove duplicate SYN attempts.
    tcp_packets = [
        p for p in packets
        if p.get("protocol") == "TCP"
        and p.get("timestamp") is not None
    ]

    syn_packets = []
    seen_syns = set()

    for packet in tcp_packets:
        flags = packet.get("tcp_flags") or ""

        # A SYN-only packet has S but neither A nor R.
        if "S" not in flags or "A" in flags or "R" in flags:
            continue

        key = (
            packet.get("source_ip"),
            packet.get("source_port"),
            packet.get("destination_ip"),
            packet.get("destination_port"),
            packet.get("tcp_seq"),
        )

        if key in seen_syns:
            continue

        seen_syns.add(key)
        syn_packets.append(packet)

    # TODO 2: Record SYN-ACK responses and completed handshakes.
    answered = set()
    completed = set()
    talkers = set()

    for packet in tcp_packets:
        src = packet.get("source_ip")
        dst = packet.get("destination_ip")
        sport = packet.get("source_port")
        dport = packet.get("destination_port")
        flags = packet.get("tcp_flags") or ""

        if src is not None and sport is not None:
            talkers.add((src, sport))

        if dst is not None and dport is not None:
            talkers.add((dst, dport))

        # Remember connections from the client's point of view.
        client_key = (src, sport, dst, dport)

        if "S" in flags and "A" in flags:
            # SYN-ACK: reverse the direction to identify the client.
            answered.add((dst, dport, src, sport))

        elif "A" in flags and "S" not in flags and "R" not in flags:
            # ACK: this may complete a previously initiated handshake.
            completed.add(client_key)

    # TODO 3: Group SYN-only packets by destination service.
    groups = {}

    for packet in syn_packets:
        destination = (
            packet.get("destination_ip"),
            packet.get("destination_port"),
        )

        groups.setdefault(destination, []).append(packet)

    findings = []

    for (destination_ip, destination_port), group in groups.items():

        group.sort(key=lambda p: p["timestamp"])

        if len(group) < syn_threshold:
            continue

        # TODO 4: Find the busiest sliding time window.
        left = 0
        best_left = 0
        best_right = -1

        for right in range(len(group)):
            while (
                group[right]["timestamp"] - group[left]["timestamp"]
                > window_seconds
            ):
                left += 1

            current_count = right - left + 1
            best_count = best_right - best_left + 1

            if current_count > best_count:
                best_left = left
                best_right = right

        window = group[best_left:best_right + 1]

        if len(window) < syn_threshold:
            continue

        # TODO 5: Calculate the handshake completion ratios.
        total_syns = len(window)

        completed_count = 0
        answered_count = 0

        for packet in window:
            connection = (
                packet.get("source_ip"),
                packet.get("source_port"),
                packet.get("destination_ip"),
                packet.get("destination_port"),
            )

            if connection in completed:
                completed_count += 1

            if connection in answered:
                answered_count += 1

        completed_ratio = completed_count / total_syns
        answered_ratio = answered_count / total_syns

        if completed_ratio >= completed_cutoff:
            continue

        # TODO 6: Calculate sources, rate and confidence.
        source_counts = Counter(
            packet.get("source_ip")
            for packet in window
            if packet.get("source_ip") is not None
        )

        source_ips = sorted(source_counts)
        distinct_sources = len(source_ips)

        first_seen = window[0]["timestamp"]
        last_seen = window[-1]["timestamp"]

        duration = last_seen - first_seen

        # Avoid dividing by zero when timestamps are identical.
        rate_duration = max(duration, 1e-9)
        syn_per_second = total_syns / rate_duration

        server_key = (destination_ip, destination_port)
        replies_visible = server_key in talkers

        if not replies_visible:
            confidence = "Low"
        elif (
            completed_ratio <= 0.1
            and total_syns >= 3 * syn_threshold
        ):
            confidence = "High"
        else:
            confidence = "Medium"

        severity = "High" if confidence == "High" else "Medium"

        # TODO 7: Create the finding.
        if distinct_sources == 1:
            source_description = "single source"
        else:
            source_description = f"distributed, {distinct_sources} sources"

        completion_share = (1 - completed_ratio) * 100

        title = (
            f"Possible TCP SYN flood ({source_description})"
        )

        summary = (
            f"{total_syns} SYN-only packets targeted "
            f"{destination_ip}:{destination_port} "
            f"at approximately {syn_per_second:.1f} packets per second. "
            f"Approximately {completion_share:.1f}% did not have "
            f"matching completion evidence."
        )

        explanation = (
            "A high concentration of TCP SYN-only packets targeted one "
            "service within a short time window. The low proportion of "
            "observed completed handshakes is consistent with a possible "
            "SYN flood. This finding is an indicator, not proof of an attack."
        )

        evidence = [
            f"Observed {total_syns} unique SYN-only attempts.",
            f"Identified {distinct_sources} distinct source IP addresses.",
            (
                f"SYN-ACK response ratio: {answered_ratio:.3f}; "
                f"completed handshake ratio: {completed_ratio:.3f}."
            ),
            (
                "Server replies were visible in the capture."
                if replies_visible
                else "Server replies were not visible in the capture."
            ),
        ]

        recommendation = (
            "Review server and network logs, enable SYN cookies where "
            "appropriate, apply sensible connection rate limits, and "
            "consider upstream traffic filtering if an attack is confirmed."
        )

        finding = self.finding(
            title=title,
            summary=summary,
            severity=severity,
            confidence=confidence,
            classification="inferred",
            explanation=explanation,
            evidence=evidence,
            stats={
                "syn_count": total_syns,
                "syn_per_second": round(syn_per_second, 3),
                "distinct_sources": distinct_sources,
                "answered_ratio": round(answered_ratio, 3),
                "completed_ratio": round(completed_ratio, 3),
            },
            source_ips=source_ips,
            destination_ips=[destination_ip],
            destination_ports=[destination_port],
            protocol="TCP",
            first_seen=first_seen,
            last_seen=last_seen,
            window_seconds=window_seconds,
            packet_numbers=[
                packet["packet_number"]
                for packet in window
                if packet.get("packet_number") is not None
            ],
            recommendation=recommendation,
        )

        findings.append(finding)

    return findings
