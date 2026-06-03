# DNS-Anomaly-Detector

A defensive security tool that monitors DNS traffic for signs of spoofing, poisoning,
and tunneling.

## Features

- **Packet capture:** live sniffing via Scapy or raw sockets (requires root/admin)
- **Resolver cross-checking:** queries multiple trusted resolvers and flags discrepancies
- **TTL analysis:** detects sudden TTL drops that indicate cache poisoning
- **Entropy detection:** flags high-entropy subdomains used in DNS tunneling
- **Anomaly scoring:** weighted rule engine aggregates signals into a risk score
- **SQLite persistence:** stores domain history for baseline and trend analysis
- **Rich CLI dashboard:** live feed of events with color-coded severity
- **Alert engine:** configurable thresholds trigger warnings/criticals
- **JSON & HTML export:** structured logs and human-readable reports

## Project Structure

```
dns_detector/
├── dns_detector/
│   ├── capture/
│   │   ├── sniffer.py          # Scapy-based live packet capture
│   │   ├── resolver.py         # Active resolver cross-checking
│   │   └── log_ingest.py       # Parse bind/dnsmasq log files
│   ├── analysis/
│   │   ├── ttl_analyzer.py     # TTL change & drop detection
│   │   ├── ip_baseline.py      # Cross-check IPs against trusted resolvers
│   │   ├── entropy.py          # Subdomain entropy (tunneling detection)
│   │   └── scorer.py           # Anomaly scoring engine
│   ├── storage/
│   │   ├── db.py               # SQLite event store (aiosqlite)
│   │   └── baseline_cache.py   # Known-good IP snapshot cache
│   ├── output/
│   │   ├── dashboard.py        # Rich live CLI dashboard
│   │   ├── alerts.py           # Alert threshold engine
│   │   ├── json_export.py      # Structured JSON log export
│   │   └── report.py           # HTML/PDF report generator
│   ├── config.py               # Settings (resolvers, thresholds, etc.)
│   └── main.py                 # CLI entry point (argparse)
├── tests/
│   ├── test_ttl_analyzer.py
│   ├── test_entropy.py
│   ├── test_scorer.py
│   └── fixtures/               # Sample pcap / log files for tests
├── docs/
│   └── architecture.md
├── scripts/
│   └── generate_test_traffic.py  # Dev helper: generates synthetic DNS traffic
├── pyproject.toml
└── README.md
```

## Quickstart

```bash
# Install dependencies
pip install -e ".[dev]"

# Run against a network interface (requires root)
sudo dns-detector --interface eth0

# Run in log-file mode (no root needed)
dns-detector --logfile /var/log/named/query.log

# Run with custom config
dns-detector --interface eth0 --config my_config.toml --alert-threshold 0.7
```

## Requirements

- Python 3.11+
- Root/administrator access for live capture mode
- See `pyproject.toml` for full dependency list

## Detection Methods

| Method | What it catches | Data needed |
| -------- | ---------------- | ------------- |
| TTL drop analysis | Cache poisoning attempts | Live capture or logs |
| Multi-resolver cross-check | Active spoofing / MITM | Active resolver queries |
| Subdomain entropy | DNS tunneling (data exfil) | Any DNS traffic |
| IP geolocation shift | Hijacking to foreign infra | Baseline + live data |
| Response timing anomaly | Forged fast responses | Live capture |

## Scoring

Each detection method contributes a weighted signal (0.0–1.0). The anomaly scorer
combines them into a final risk score. Scores above configurable thresholds trigger
`WARNING` (0.5) or `CRITICAL` (0.8) alerts.
