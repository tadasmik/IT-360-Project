# LogonForensics

A lightweight Windows **EVTX logon forensic analyzer** for IT 360 Final Project:
*SIEM Detection and Forensic Analysis of a Simulated Account Compromise.*

## Project overview

This tool parses a Windows Security event log (`.evtx`), extracts
authentication events, verifies the evidence file's integrity, and produces an
independent, hash-verified incident timeline. It was built to **corroborate
automated / AI-assisted SIEM output against the raw logs**. During our simulated
incident, the AI analysis tool reported only 3 failed logins when 4 actually
occurred; running the raw EVTX through this tool recovers the true count and
timeline, demonstrating a concrete limitation of AI-assisted forensics.

## Features

- SHA-256 hashing of the evidence file for chain-of-custody / integrity verification.
- Parses Event ID **4625** (failed logon) and **4624** (successful logon).
- Decodes logon types (Interactive, Network, RDP, etc.) and failure sub-status
  codes (e.g. `0xC000006A` = incorrect password) into plain English.
- Filters by account name (`--user`).
- Converts UTC timestamps to local time (`--utc-offset`).
- Prints a summary count and a chronological incident timeline.
- Optional CSV export (`--csv`) for inclusion in the report.

## Setup

Requires Python 3.8+.

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Full analysis of a Security log
python src/logon_analyzer.py data/sample_security.evtx

# Only a specific account, times shown in CST (UTC-6), export a CSV
python src/logon_analyzer.py data/sample_security.evtx \
    --user ForensicTest --utc-offset -6 --csv data/timeline.csv
```

### Example output

```
Failed logons (4625)  : 4
Successful logons (4624): 1
Incident timeline:
  2026-11-16 16:26:22  [4625 FAILED]  user=DESKTOP-SM6ACEE\ForensicTest  type=2(Interactive)  src=::1  reason=Incorrect password
  ...
  2026-11-16 16:34:48  [4624 SUCCESS] user=DESKTOP-SM6ACEE\ForensicTest  type=2(Interactive)  src=::1
```

## Repository structure

```
LogonForensics/
  src/logon_analyzer.py      # the tool
  docs/                      # final report + presentation slides (PDF)
  data/                      # sample evidence + generated timeline CSV
  requirements.txt
  README.md
  LICENSE
```

## Limitations

- Focuses on logon events (4624/4625); does not yet parse account-management
  (4720/4726) or object-access events.
- Reads a single EVTX file at a time.

## Authors

IT 360 — Tadas (Digital Forensics & Reporting Lead) and Josh (SIEM & Incident Analysis Lead).
