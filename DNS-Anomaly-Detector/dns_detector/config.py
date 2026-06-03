"""
Central configuration for dns-anomaly-detector.
Loaded from a TOML file; each section maps to a dataclass.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ResolverConfig:
    # Trusted resolvers used for cross-checking
    trusted: list[str] = field(default_factory=lambda: [
        "8.8.8.8",    # Google
        "1.1.1.1",    # Cloudflare
        "9.9.9.9",    # Quad9
        "208.67.222.222",  # OpenDNS
    ])
    timeout_seconds: float = 2.0
    # Number of resolvers that must agree for a result to be "trusted"
    quorum: int = 3


@dataclass
class ThresholdConfig:
    # Anomaly score thresholds (0.0 – 1.0)
    warning: float = 0.5
    critical: float = 0.8

    # TTL drop ratio that triggers suspicion (e.g. 0.5 = 50% drop)
    ttl_drop_ratio: float = 0.5
    # Minimum TTL to track (ignore very short TTLs by design, e.g. CDNs)
    ttl_min_track_seconds: int = 30

    # Shannon entropy threshold for subdomain tunneling detection
    entropy_warning: float = 3.5
    entropy_critical: float = 4.2

    # Minimum number of IP changes before flagging geolocation shift
    ip_change_count: int = 3


@dataclass
class StorageConfig:
    db_path: Path = Path("dns_detector.db")
    # How many days of history to retain
    retention_days: int = 30


@dataclass
class OutputConfig:
    # Dashboard refresh rate in seconds
    dashboard_refresh: float = 1.0
    # JSON log file path (None = stdout)
    json_log_path: Path | None = None
    # Report output directory
    report_dir: Path = Path("reports")


@dataclass
class AppConfig:
    resolver: ResolverConfig = field(default_factory=ResolverConfig)
    threshold: ThresholdConfig = field(default_factory=ThresholdConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    # Network interface for live capture (e.g. "eth0", "en0")
    interface: str | None = None
    # Log file path for offline analysis
    log_file: Path | None = None

    @classmethod
    def load(cls, path: Path) -> "AppConfig":
        """Load config from a TOML file, falling back to defaults."""
        if not path.exists():
            return cls()
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        cfg = cls()
        if "resolver" in raw:
            r = raw["resolver"]
            cfg.resolver.trusted = r.get("trusted", cfg.resolver.trusted)
            cfg.resolver.timeout_seconds = r.get("timeout_seconds", cfg.resolver.timeout_seconds)
            cfg.resolver.quorum = r.get("quorum", cfg.resolver.quorum)
        if "threshold" in raw:
            t = raw["threshold"]
            cfg.threshold.warning = t.get("warning", cfg.threshold.warning)
            cfg.threshold.critical = t.get("critical", cfg.threshold.critical)
            cfg.threshold.ttl_drop_ratio = t.get("ttl_drop_ratio", cfg.threshold.ttl_drop_ratio)
            cfg.threshold.entropy_warning = t.get("entropy_warning", cfg.threshold.entropy_warning)
            cfg.threshold.entropy_critical = t.get("entropy_critical", cfg.threshold.entropy_critical)
        if "storage" in raw:
            s = raw["storage"]
            cfg.storage.db_path = Path(s.get("db_path", cfg.storage.db_path))
            cfg.storage.retention_days = s.get("retention_days", cfg.storage.retention_days)
        return cfg