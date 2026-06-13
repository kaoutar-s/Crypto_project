# Usage Guide

## Requirements

Install project dependencies:

```bash
python -m pip install -r requirements.txt
```

On this local Windows workspace, dependencies may be installed into `.deps`. In that case, run:

```powershell
$env:PYTHONPATH='.deps'
$env:PYTHONDONTWRITEBYTECODE='1'
```

## Analyze a PCAP File

Run the full extraction and detection pipeline:

```bash
python code.py --pcap test.pcap --sessions-out sessions_tls.json --alerts-out alerts.json
```

This creates:

```text
sessions_tls.json
alerts.json
```

## Analyze Existing Sessions

If `sessions_tls.json` already exists:

```bash
python code.py --sessions sessions_tls.json --alerts-out alerts.json
```

## Sign and Store Alerts

After alerts are generated:

```bash
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
```

This creates or updates:

```text
alerts.db
report.json
keys/private_key.pem
keys/public_key.pem
```

## Run the Dashboard

Start the Flask dashboard:

```bash
python -m partie_4_dashboard.app
```

Open:

```text
http://127.0.0.1:5000/
```

## Typical Full Workflow

```powershell
cd "C:\Users\taele\OneDrive\Documents\IDS project"
$env:PYTHONPATH='.deps'
$env:PYTHONDONTWRITEBYTECODE='1'

python code.py --pcap test.pcap --sessions-out sessions_tls.json --alerts-out alerts.json
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
python -m partie_4_dashboard.app
```
