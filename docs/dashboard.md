# Dashboard Guide

## Overview

The dashboard is a local Flask prototype for visualizing IDS alerts.

Folder:

```text
partie_4_dashboard/
```

Main file:

```text
partie_4_dashboard/app.py
```

## Run

```bash
python -m partie_4_dashboard.app
```

Open:

```text
http://127.0.0.1:5000/
```

## Data Sources

The dashboard loads data in this priority order:

```text
1. report.json
2. alerts.json
3. alerts.db
```

If `report.json` exists, it is used first because it contains the signed report output from Part 3.

## Current Views

The dashboard currently shows:

- total alert count
- critical alert count
- warning alert count
- info alert count
- alert table
- alert type summary
- top source IP summary
- severity filter
- text search

## Future Improvements

Recommended improvements for the final dashboard:

- alert detail page
- report verification status
- date range filtering
- severity charts
- JA3/JA3S search
- source/destination IP drilldown
- upload form for PCAP files
- button to run the IDS pipeline from the dashboard
