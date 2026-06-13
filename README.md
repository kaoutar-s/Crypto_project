# Crypto Project - TLS IDS

Crypto Project is a modular TLS Intrusion Detection System. It extracts TLS metadata from packet captures, analyzes sessions with rule-based detection, signs and stores alerts, and exposes a local dashboard for visualization.

## Features

- TLS packet extraction from PCAP files
- ClientHello and ServerHello parsing
- SNI, TLS version, cipher suite, certificate, JA3, and JA3S metadata extraction
- Rule-based detection engine for weak or suspicious TLS behavior
- Signed alert storage with SQLite
- Signed JSON report export
- Local Flask dashboard prototype

## Project Structure

```text
part1_extraction/       TLS capture, parsing, session extraction
partie2_moteursoc/      Detection rules and alert generation
partie_3/               Alert signing, verification, database, reports
partie_4_dashboard/     Local dashboard prototype
docs/                   Technical and usage documentation
code.py                 End-to-end command-line pipeline
```

## Quick Start

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the pipeline on a PCAP file:

```bash
python code.py --pcap test.pcap --sessions-out sessions_tls.json --alerts-out alerts.json
```

Sign alerts, store them, and export a report:

```bash
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
```

Run the local dashboard:

```bash
python -m partie_4_dashboard.app
```

Open:

```text
http://127.0.0.1:5000/
```

## Documentation

- [Architecture](docs/architecture.md)
- [Usage Guide](docs/usage.md)
- [Testing Guide](docs/testing.md)
- [Dashboard Guide](docs/dashboard.md)
- [Documentation Index](DOCUMENTATION.md)

## Notes

This project analyzes TLS metadata. It does not decrypt HTTPS application data.
