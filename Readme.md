# SIEM Dashboard

## Overview
A lightweight, high-performance Security Information and Event Management (SIEM) platform built natively in **Go** with a **zero-build, minimal web interface** (Pico.css + HTMX + SSE).

The system ingests logs from multiple sources via Syslog (UDP/TCP) and file parsing, normalizes them into standard security events, analyzes streams using an in-memory correlation rule engine, and presents real-time security alerts and incident metrics in an interactive web dashboard. All assets and templates are embedded into a single, self-contained binary.

---

## Architecture & Tech Stack

- **Language & Runtime:** Go (Golang) — concurrency via Goroutines and buffered channels.
- **Log Ingestion:** Go standard library `net.ListenUDP` & `net.ListenTCP` (Syslog RFC 3164 / RFC 5424) + file watcher.
- **Storage:** SQLite (fast, embedded, single-file relational database).
- **Rule Engine:** In-memory sliding window state tracker with configurable detection rules (YAML/JSON).
- **Web Server:** Go `net/http` standard library with `html/template` and `embed.FS`.
- **Frontend / UI:** 
  - **Pico.css:** Semantic, classless CSS providing a clean, dark-mode security console without frontend build tools.
  - **HTMX + SSE (Server-Sent Events):** Real-time log streaming, filtering, and tab updates without writing client-side JavaScript frameworks.
  - **Chart.js:** Lightweight visualization for event timelines and severity distributions.

---

## Directory Layout

```text
.
├── cmd/
│   └── siem/
│       └── main.go          # Main entrypoint: orchestrates ingestion, storage, and web server
├── internal/
│   ├── ingestion/           # UDP/TCP Syslog receivers and file tailers
│   ├── parser/              # Log normalization and schema parsing (RFC 3164/5424)
│   ├── correlation/         # State tracking & sliding-window security rule engine
│   ├── storage/             # SQLite connection, migrations, and event queries
│   └── web/                 # HTTP handlers, SSE hub, and template rendering
│       ├── static/          # Embedded vendor assets (pico.min.css, htmx.min.js, sse.js, chart.umd.min.js)
│       └── templates/       # HTML templates (base layout, dashboard, alert rows)
├── go.mod
└── Readme.md
```

---

## Step-by-Step Roadmap

1. **Log Ingestion Pipeline:**
   - Implement concurrent UDP/TCP Syslog receivers on port 514 (configurable).
   - Read incoming datagrams asynchronously into a buffered channel to prevent packet dropping.
   - Build a pluggable parser to parse common Syslog formats into a normalized schema (`Timestamp`, `SourceIP`, `DestinationIP`, `Severity`, `EventType`, `Message`, `Raw`).

2. **Storage Layer:**
   - Configure embedded SQLite database with indexed tables for events and generated security alerts.
   - Batch database inserts from ingestion channels for optimal write throughput.

3. **Event Correlation Rule Engine:**
   - Create an in-memory rule engine matching sequences of events across sliding time windows (e.g. "5 failed logins followed by a success within 60s from the same IP").
   - Support rule definitions via clean configuration structs/files.
   - Dispatch triggered alerts to the alert channel.

4. **Web Interface & Real-time Live Stream:**
   - Serve server-rendered HTML templates via `html/template`.
   - Implement an SSE endpoint (`/events/stream`) that broadcasts incoming alerts and logs.
   - Use HTMX SSE extensions to prepend incoming alerts to the dashboard table dynamically with zero client-side framework code.

5. **Search, Filtering & Forensics:**
   - Provide query filters by severity, source IP, time window, and event type.
   - HTMX-driven live filtering swapping only table fragments.
   - Pivot views: inspect all events associated with a specific IP or user.

6. **Metrics & Visualizations:**
   - Aggregations for event volume trends, severity breakdowns, and top talkers rendered using Chart.js.

---

## Deliverables
- Single executable Go binary (`siem`) with embedded web assets.
- UDP/TCP Syslog receiver and parser.
- Sliding window security correlation engine.
- SQLite-backed log repository.
- HTMX + Pico.css real-time monitoring dashboard.
- Configurable security detection rules.
