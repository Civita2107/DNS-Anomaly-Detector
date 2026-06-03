"""
Shared data models for dns-anomaly-detector.
All modules import from here to avoid circular dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class DetectionMethod(str, Enum):
    TTL_DROP = "ttl_drop"
    IP_MISMATCH = "ip_mismatch"
    ENTROPY = "entropy"
    GEO_SHIFT = "geo_shift"
    TIMING = "timing"


@dataclass
class DnsEvent:
    # A single observed DNS query/response pair
    
    timestamp: datetime
    domain: str
    query_type: str          # it can be A, AAAA, MX, TXT, etc.
    source_ip: str
    resolver_ip: str
    resolved_ips: list[str]
    ttl: int                 # in seconds
    raw_ttl: int             # original TTL before any caching


@dataclass
class Anomaly:
    # A detected anomaly produced by one of the analysis modules
    
    timestamp: datetime
    domain: str
    method: DetectionMethod
    severity: Severity
    score: float             # 0.0 – 1.0 contribution from this method
    detail: str              
    event: DnsEvent | None = None


@dataclass
class AnomalyReport:
    # Aggregated result from the scoring engine for a single domain/event
    
    timestamp: datetime
    domain: str
    final_score: float
    severity: Severity
    anomalies: list[Anomaly] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return self.severity == Severity.INFO and self.final_score < 0.3