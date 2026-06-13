# Project Documentation Index

The documentation has been reorganized into focused files under the `docs/` directory.

## Documentation Files

- [Architecture](docs/architecture.md): explains the four project parts and data flow.
- [Usage Guide](docs/usage.md): explains how to run the pipeline and dashboard.
- [Testing Guide](docs/testing.md): explains how to test with sample and real PCAP files.
- [Dashboard Guide](docs/dashboard.md): explains the local dashboard prototype and future improvements.

## System Summary

```text
PCAP file
  -> Part 1: TLS metadata extraction
  -> Part 2: detection engine
  -> Part 3: signing, storage, and report export
  -> Part 4: dashboard visualization
```

The project analyzes TLS metadata only. It does not decrypt HTTPS application data.
