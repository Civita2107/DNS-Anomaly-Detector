"""
TTL Analyzer
============
Detects sudden TTL drops that are a common indicator of DNS cache poisoning.

How it works
------------
For each domain we maintain a rolling history of observed TTL values.
A significant drop (e.g. from 3600s to 30s) suggests someone is poisoning
the cache with a spoofed record that will expire quickly, allowing re-poisoning.

Detection signals
-----------------
- TTL drop ratio: (previous_ttl - current_ttl) / previous_ttl > threshold
- Absolute floor: current_ttl < MIN_SUSPICIOUS_TTL (e.g. < 30s outside CDNs)
- Oscillation: TTL bounces rapidly between high and low values
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from dns_detector.models import Anomaly, DetectionMethod, DnsEvent, Severity


@dataclass
class TtlRecord:
    ttl: int
    observed_at: datetime


@dataclass
class TtlAnalyzer:
    # Maintains per-domain TTL history and emits Anomaly objects when a suspicious TTL change is detected
    
    drop_ratio_threshold: float = 0.5 # Fraction of drop to trigger warning (0.0-1.0)
    min_track_seconds: int = 30 # Ignore TTLs below this (CDN / intentional short TTLs)
    history_size: int = 10 # How many TTL observations to keep per domain

    _history: dict[str, deque[TtlRecord]] = field(default_factory=dict, init=False)

    def analyze(self, event: DnsEvent) -> list[Anomaly]:
        # Process a DNS event and return any TTL-related anomalies found
        
        anomalies: list[Anomaly] = []
        domain = event.domain
        current_ttl = event.ttl

        if domain not in self._history:
            self._history[domain] = deque(maxlen=self.history_size)

        history = self._history[domain]

        if history:
            prev = history[-1].ttl
            anomaly = self._check_drop(event, prev, current_ttl)
            if anomaly:
                anomalies.append(anomaly)

            if len(history) >= 3:
                oscillation = self._check_oscillation(domain, event, list(history))
                if oscillation:
                    anomalies.append(oscillation)

        # Record this TTL only if it's above the minimum tracking threshold 
        if current_ttl >= self.min_track_seconds:
            history.append(TtlRecord(ttl=current_ttl, observed_at=event.timestamp))

        return anomalies

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_drop(self, event: DnsEvent, prev_ttl: int, current_ttl: int) -> Anomaly | None:
        # Flag a significant drop from the previously-seen TTL
        if prev_ttl == 0:
            return None
        drop_ratio = (prev_ttl - current_ttl) / prev_ttl
        if drop_ratio < self.drop_ratio_threshold:
            return None

        score = min(1.0, (drop_ratio - self.drop_ratio_threshold) / (1.0 - self.drop_ratio_threshold))
        severity = Severity.CRITICAL if score >= 0.7 else Severity.WARNING

        return Anomaly(
            timestamp=event.timestamp,
            domain=event.domain,
            method=DetectionMethod.TTL_DROP,
            severity=severity,
            score=score,
            detail=(
                f"TTL dropped from {prev_ttl}s to {current_ttl}s "
                f"({drop_ratio:.0%} reduction). "
                "Possible cache poisoning attempt."
            ),
            event=event,
        )

    def _check_oscillation(
        self, domain: str, event: DnsEvent, recent: list[TtlRecord]
    ) -> Anomaly | None:
        # Flag rapid oscillation in TTL values (std-dev > mean * 0.5)
        ttls = [r.ttl for r in recent[-5:]]  # last 5 observations
        if len(ttls) < 3:
            return None

        mean = sum(ttls) / len(ttls)
        if mean == 0:
            return None

        variance = sum((t - mean) ** 2 for t in ttls) / len(ttls)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean  # coefficient of variation

        if cv < 0.5:
            return None

        score = min(1.0, cv / 2.0)
        return Anomaly(
            timestamp=event.timestamp,
            domain=domain,
            method=DetectionMethod.TTL_DROP,
            severity=Severity.WARNING,
            score=score,
            detail=(
                f"TTL oscillating unusually (CV={cv:.2f}). "
                f"Recent values: {ttls}. Possible cache manipulation."
            ),
            event=event,
        )