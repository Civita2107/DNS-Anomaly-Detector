"""
Entropy Analyzer
================
Detects DNS tunneling by measuring the Shannon entropy of domain labels.

How it works
------------
DNS tunneling tools (iodine, dns2tcp, dnscat) encode data in subdomain labels.
Base64/hex-encoded payloads have near-maximum entropy (~4.0 bits/char for
random lowercase+digits), while natural language hostnames are low-entropy
(e.g. "www", "mail", "api" → ~1.5–2.5 bits/char).

Example
-------
    Legitimate:   "www.example.com"        → entropy ≈ 1.79
    Tunneling:    "aGVsbG8xMjM.evil.com"   → entropy ≈ 4.01
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from ..models import Anomaly, DetectionMethod, DnsEvent, Severity


def shannon_entropy(s: str) -> float:
    """
    Compute Shannon entropy of a string in bits per character.
    Returns 0.0 for empty or single-character strings.
    """
    if len(s) <= 1:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
    )


@dataclass
class EntropyAnalyzer:
    # Flags domains whose subdomains show entropy consistent with base64/hex-encoded DNS tunnel payloads.

    warning_threshold: float = 3.5 # Entropy level that triggers a WARNING
    critical_threshold: float = 4.2 # Entropy level that triggers a CRITICAL
    min_label_length: int = 8 # Ignore very short labels

    def analyze(self, event: DnsEvent) -> list[Anomaly]:
        # Analyze the domain in a DNS event for high-entropy labels
        
        labels = event.domain.rstrip(".").split(".")
        # Skip TLD and registered domain — focus on subdomains
        subdomains = labels[:-2] if len(labels) > 2 else []

        suspicious: list[tuple[str, float]] = []
        for label in subdomains:
            if len(label) < self.min_label_length:
                continue
            e = shannon_entropy(label)
            if e >= self.warning_threshold:
                suspicious.append((label, e))

        if not suspicious:
            return []

        # Use the highest-entropy label as the signal
        worst_label, worst_entropy = max(suspicious, key=lambda x: x[1])

        if worst_entropy >= self.critical_threshold:
            severity = Severity.CRITICAL
            score = min(1.0, (worst_entropy - self.critical_threshold) / 1.0 + 0.8)
        else:
            severity = Severity.WARNING
            score = (worst_entropy - self.warning_threshold) / (
                self.critical_threshold - self.warning_threshold
            ) * 0.5 + 0.3

        score = min(1.0, max(0.0, score))

        return [
            Anomaly(
                timestamp=event.timestamp,
                domain=event.domain,
                method=DetectionMethod.ENTROPY,
                severity=severity,
                score=score,
                detail=(
                    f"High-entropy subdomain label '{worst_label}' "
                    f"(entropy={worst_entropy:.2f} bits/char). "
                    "Possible DNS tunneling."
                ),
                event=event,
            )
        ]