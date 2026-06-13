# Architecture

## Overview

The project is organized as a four-part TLS IDS pipeline.

```text
PCAP file or live capture
  -> Part 1: TLS metadata extraction
  -> sessions_tls.json
  -> Part 2: Detection engine
  -> alerts.json
  -> Part 3: Signing, storage, and reporting
  -> alerts.db / report.json
  -> Part 4: Dashboard visualization
```

The system analyzes TLS metadata only. It does not decrypt HTTPS payloads.

## Part 1 - TLS Extraction

Folder:

```text
part1_extraction/
```

Part 1 reads a PCAP file or network capture and extracts TLS session metadata.

Main responsibilities:

- read PCAP packets
- filter TLS traffic on TCP port 443
- detect ClientHello and ServerHello messages
- parse TLS versions, SNI, cipher suites, and extensions
- extract certificates when available
- calculate JA3 and JA3S fingerprints
- produce structured TLS sessions

Important files:

```text
capture.py       Packet capture and PCAP loading
tls_parser.py    ClientHello and ServerHello parsing
cert_parser.py   X.509 certificate extraction and analysis
ja3.py           JA3 and JA3S fingerprint calculation
session.py       Session orchestration and JSON export
```

Output:

```text
sessions_tls.json
```

## Part 2 - Detection Engine

Folder:

```text
partie2_moteursoc/
```

Part 2 receives TLS session objects and generates alerts.

Main responsibilities:

- normalize TLS session data from Part 1
- apply security rules
- detect weak TLS versions and ciphers
- detect certificate issues
- detect suspicious or missing SNI
- detect blacklisted JA3 and JA3S fingerprints
- produce alert objects compatible with Part 3

Important files:

```text
rules.py          Rule constants, thresholds, blacklists
detector.py       Main TLSDetector analysis logic
alert_engine.py   Standard alert creation
main.py           Standalone Part 2 demo
```

Output:

```text
alerts.json
```

## Part 3 - Signing, Storage, and Reports

Folder:

```text
partie_3/
```

Part 3 protects alert integrity and stores results.

Main responsibilities:

- generate ECDSA private/public keys
- sign generated alerts
- verify signed alerts
- store alerts in SQLite
- export signed JSON reports

Important files:

```text
key_manager.py    Key generation and loading
signer.py         Alert signing
verifier.py       Signature verification
database.py       SQLite storage
exporter.py       Signed report export
```

Outputs:

```text
alerts.db
report.json
keys/private_key.pem
keys/public_key.pem
```

## Part 4 - Dashboard

Folder:

```text
partie_4_dashboard/
```

Part 4 is a local Flask dashboard prototype. It visualizes generated IDS data and can later be replaced or extended by the dashboard team.

Current capabilities:

- load alerts from `report.json`, `alerts.json`, or `alerts.db`
- display alert totals by severity
- display alert type counts
- display source IP summaries
- filter alerts by severity
- search across alert content

## Integration File

File:

```text
code.py
```

This is the main command-line entrypoint that connects Parts 1, 2, and 3.

It supports:

- PCAP extraction
- existing session JSON analysis
- alert JSON export
- optional signing and database storage
- optional signed report export
