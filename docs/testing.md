# Testing Guide

## Test Levels

The project can be tested at three levels:

1. Pipeline test with the included `test.pcap`
2. Signature and report test with Part 3
3. Real capture test with a PCAP or PCAPNG file from Wireshark

## 1. Pipeline Test

Run:

```powershell
python code.py --pcap test.pcap --sessions-out sessions_tls.json --alerts-out alerts.json
```

Expected result:

```text
sessions_tls.json is created or updated
alerts.json is created or updated
terminal prints number of sessions and alerts
```

## 2. Signature and Report Test

Run:

```powershell
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
```

Expected result:

```text
alerts.db is created or updated
report.json is created or updated
keys/ contains ECDSA keys
```

## 3. Dashboard Test

Run:

```powershell
python -m partie_4_dashboard.app
```

Open:

```text
http://127.0.0.1:5000/
```

Expected result:

```text
dashboard loads successfully
alert counters are visible
alert table is visible
severity filter works
search input works
```

## 4. Real Capture Test

Use Wireshark:

1. Start capture on `Wi-Fi` or `Ethernet`.
2. Open a few HTTPS websites after capture starts.
3. Stop capture after 20 to 40 seconds.
4. Save the file as `capture_test.pcapng` or `capture_test.pcap`.
5. Put the file in the project root.

Run:

```powershell
python code.py --pcap capture_test.pcapng --sessions-out sessions_tls.json --alerts-out alerts.json
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
```

Then reload the dashboard.

## Important Capture Notes

The extractor needs to see the beginning of the TLS connection, especially the ClientHello. Start Wireshark before opening the HTTPS websites.

The system extracts TLS metadata only. It does not decrypt HTTPS content.
