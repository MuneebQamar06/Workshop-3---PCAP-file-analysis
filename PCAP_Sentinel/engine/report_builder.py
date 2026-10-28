
"""TASK 3 - Report builder: turn context and rule findings into a dashboard report."""

from collections import Counter
from datetime import datetime, timezone
from typing import Any, List, Optional

SEVERITIES = ("High", "Medium", "Low", "Informational")
CONFIDENCES = ("High", "Medium", "Low")
CLASSIFICATIONS = ("observed", "indicator", "inferred")

SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}

STATIC_LIMITATIONS = [
    "No findings does not mean a capture is safe: this is a rule-based educational detector covering a documented set of common behaviours, not a full IDS.",
    "Encrypted traffic (HTTPS, SSH, FTPS, DoH) cannot be inspected; only metadata is available for it.",
    "Findings are indicators for a human to verify (for example in Wireshark and server logs), not proof of compromise or of service impact.",
    "Rates and time windows use the packet timestamps stored in the capture; missing, duplicated or dropped packets can change results.",
]


def _jsonable(value: Any) -> Any:
    """Convert values into types that JSON can represent."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, float) and value != value:
        return None
    if isinstance(value, float) and value in (float("inf"), float("-inf")):
        return None
    return (
        value
        if isinstance(value, (str, int, float, bool)) or value is None
        else str(value)
    )


def _utc(timestamp: Optional[float]) -> Optional[str]:
    """Convert epoch seconds into an ISO-8601 UTC timestamp."""
    if timestamp is None:
        return None

    try:
        return datetime.fromtimestamp(
            float(timestamp), tz=timezone.utc
        ).isoformat()
    except (TypeError, OverflowError, OSError, ValueError):
        return None


def _elapsed(timestamp: Optional[float],
             start: Optional[float]) -> Optional[float]:
    """Return seconds after capture start, or None if unavailable."""
    if timestamp is None or start is None:
        return None

    try:
        return round(float(timestamp) - float(start), 3)
    except (TypeError, ValueError, OverflowError):
        return None


def normalise_finding(
    raw: dict,
    start: Optional[float],
    number: int,
) -> dict:
    """Fill missing finding fields and repair invalid values."""
    item = dict(raw)
    notes = list(item.get("normalisation_notes") or [])

    # Repair invalid severity.
    if item.get("severity") not in SEVERITIES:
        item["severity"] = "Low"
        notes.append("Invalid or missing severity was changed to Low.")

    # Repair invalid confidence.
    if item.get("confidence") not in CONFIDENCES:
        item["confidence"] = "Low"
        notes.append("Invalid or missing confidence was changed to Low.")

    # Repair invalid classification.
    if item.get("classification") not in CLASSIFICATIONS:
        item["classification"] = "indicator"
        notes.append(
            "Invalid or missing classification was changed to indicator."
        )

    # Provide safe defaults for fields used by the dashboard.
    defaults = {
        "rule_id": "",
        "name": "",
        "category": "",
        "summary": "",
        "explanation": "",
        "evidence": [],
        "stats": {},
        "source_ips": [],
        "destination_ips": [],
        "source_ports": [],
        "destination_ports": [],
        "protocol": "",
        "window_seconds": None,
        "packet_numbers": [],
        "packet_count": None,
        "recommendation": "",
        "limitations": [],
        "false_positive_risk": "",
        "thresholds": {},
    }

    for key, default in defaults.items():
        if key not in item or item[key] is None:
            item[key] = default.copy() if isinstance(default, (list, dict)) else default

    # Keep packet_count consistent when it was not supplied.
    if item["packet_count"] is None:
        try:
            item["packet_count"] = len(item["packet_numbers"])
        except TypeError:
            item["packet_count"] = 0

    # Normalise the two timestamps before removing the original fields.
    first_seen = item.get("first_seen")
    last_seen = item.get("last_seen")

    item["first_seen_elapsed"] = _elapsed(first_seen, start)
    item["last_seen_elapsed"] = _elapsed(last_seen, start)
    item["first_seen_utc"] = _utc(first_seen)
    item["last_seen_utc"] = _utc(last_seen)

    item.pop("first_seen", None)
    item.pop("last_seen", None)

    item["id"] = f"F{number}"
    item["normalisation_notes"] = notes

    return _jsonable(item)


def build_observations(summary: dict) -> List[dict]:
    """Create general capture observations, separate from security findings."""
    summary = summary or {}
    totals = summary.get("totals") or {}
    capture = summary.get("capture") or {}
    tcp = summary.get("tcp") or {}
    apps = summary.get("application_protocols") or {}
    data_quality = summary.get("data_quality") or {}

    packet_count = totals.get("packets")

    # An empty capture gets exactly one observation.
    if packet_count == 0:
        return [{
            "level": "warning",
            "title": "Empty capture",
            "detail": "No packets were found in this capture.",
        }]

    observations = []

    # Capture duration.
    duration = capture.get("duration_seconds")
    if duration is None:
        duration_text = "duration unavailable"
    else:
        duration_text = f"duration {duration} seconds"

    observations.append({
        "level": "info",
        "title": "Capture overview",
        "detail": (
            f"Packets: {packet_count if packet_count is not None else 'unavailable'}; "
            f"captured bytes: "
            f"{totals.get('captured_bytes') if totals.get('captured_bytes') is not None else 'unavailable'}; "
            f"{duration_text}."
        ),
    })

    # TCP behaviour.
    tcp_packet_count = tcp.get("packets")
    attempts = tcp.get("connection_attempts")
    resets = tcp.get("reset_packets")
    retransmissions = tcp.get("retransmissions")

    if any(value is not None for value in (
        tcp_packet_count, attempts, resets, retransmissions
    )):
        details = []
        if attempts is not None:
            details.append(f"connection attempts: {attempts}")
        if resets is not None:
            details.append(f"reset packets: {resets}")
        if retransmissions is not None:
            details.append(f"retransmissions: {retransmissions}")

        observations.append({
            "level": "info",
            "title": "TCP behaviour",
            "detail": (
                "; ".join(details)
                if details
                else "TCP statistics are partially unavailable."
            ),
        })

    # Encrypted traffic.
    tls_connections = apps.get("tls_connections")
    if tls_connections is not None and tls_connections > 0:
        observations.append({
            "level": "info",
            "title": "Encrypted traffic",
            "detail": (
                f"The capture reports {tls_connections} TLS connection(s). "
                "Encrypted content is not readable from packet metadata alone."
            ),
        })

    # Application-layer visibility.
    application_payloads = apps.get("packets_with_application_payload")
    if application_payloads == 0:
        observations.append({
            "level": "warning",
            "title": "No application-layer visibility",
            "detail": (
                "No packets were recorded as containing application-layer payload. "
                "The capture may contain headers only or encrypted traffic."
            ),
        })

    # Data-quality observations.
    for key, label in (
        ("truncated", "Truncated packets"),
        ("malformed", "Malformed packets"),
        ("unsupported", "Unsupported packets"),
    ):
        count = data_quality.get(key)
        if count is not None and count > 0:
            observations.append({
                "level": "warning",
                "title": "Data quality",
                "detail": f"{label}: {count}. Some analysis may be incomplete.",
            })

    for warning in data_quality.get("warnings") or []:
        observations.append({
            "level": "warning",
            "title": "Data quality",
            "detail": str(warning),
        })

    for note in data_quality.get("notes") or []:
        observations.append({
            "level": "info",
            "title": "Data quality",
            "detail": str(note),
        })

    return observations


def build_report(context: dict, findings: List[dict]) -> dict:
    """Build the complete JSON-safe report used by the dashboard."""
    context = context or {}
    summary = context.get("summary") or {}
    capture = summary.get("capture") or {}
    start = capture.get("first_timestamp")

    raw_findings = []

    # Sort raw findings before assigning their final IDs.
    for raw in findings or []:
        raw = raw or {}
        severity = raw.get("severity")
        if severity not in SEVERITIES:
            severity = "Low"

        timestamp = raw.get("first_seen")

        # Findings without a timestamp go after timed findings
        # of the same severity.
        try:
            time_missing = timestamp is None
            sort_time = float(timestamp) if timestamp is not None else 0.0
        except (TypeError, ValueError, OverflowError):
            time_missing = True
            sort_time = 0.0

        raw_findings.append((
            SEVERITY_ORDER[severity],
            time_missing,
            sort_time,
            raw,
        ))

    raw_findings.sort(key=lambda row: (row[0], row[1], row[2]))

    normalised = [
        normalise_finding(row[3], start, index)
        for index, row in enumerate(raw_findings, start=1)
    ]

    # Count every supported category, including categories with zero findings.
    by_severity = {severity: 0 for severity in SEVERITIES}
    by_classification = {
        classification: 0 for classification in CLASSIFICATIONS
    }

    for finding in normalised:
        by_severity[finding["severity"]] += 1
        by_classification[finding["classification"]] += 1

    finding_count = len(normalised)

    if finding_count:
        severity_summary = [
            f"{count} {severity}"
            for severity, count in by_severity.items()
            if count > 0
        ]
        headline = (
            f"{finding_count} finding(s) for review: "
            + ", ".join(severity_summary)
            + "."
        )
    else:
        headline = (
            "No findings were detected. This does not prove that "
            "the capture is benign or safe."
        )

    report = {
        "schema_version": "2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "capture": dict(capture),
        "headline": headline,
        "counts": {
            "findings": finding_count,
            "by_severity": by_severity,
            "by_classification": by_classification,
        },
        "observations": build_observations(summary),
        "statistics": summary,
        "findings": normalised,
        "rules_run": context.get("rules_run") or [],
        "rule_errors": context.get("rule_errors") or [],
        "processing_errors": context.get("processing_errors") or [],
        "limitations": list(STATIC_LIMITATIONS),
    }

    return _jsonable(report)
