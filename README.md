# IT 360 Final Project: SIEM Detection and Forensic Analysis of a Simulated Account Compromise

**Authors:** Tadas Mikalauskas (Digital Forensics & Reporting Lead) and Joshua Adekoya (SIEM & Incident Analysis Lead)
**Course:** IT 360

## Overview

This project investigates a simulated account compromise staged in a controlled virtual lab on a Windows 11 system. A test account (`ForensicTest`) was created, subjected to four failed logon attempts followed by one successful logon, and a sensitive file was then modified. We analyzed the Windows Security event log and file integrity evidence using two independently written Python forensic tools, and we compared our findings against an AI analysis tool (Sushi AI).

**Key finding:** Both tools independently confirmed all four failed logons and the one successful logon, while Sushi AI reported only three of the four failed logons in both tests. Sushi also incorrectly flagged our intentional file modification as unauthorized. This demonstrates that AI/SIEM output must be corroborated against raw evidence rather than trusted on its own.

## Tools

Two independent analyzers are included, one written by each team member. They reach the same conclusion from different inputs, which strengthens the result.

### 1. `src/logon_analyzer.py` (Tadas Mikalauskas)

Parses the raw binary Windows Security event log (`.evtx`) directly.

- Computes and verifies the SHA-256 hash of the evidence file to confirm it was not altered.
- Parses Event ID 4625 (failed logon) and 4624 (successful logon) records.
- Decodes logon types (e.g. 2 = Interactive) and failure sub-status codes (e.g. 0xC000006A = Incorrect password) into plain English.
- Builds a chronological timeline and can export it to CSV.

### 2. `src/main.py` (Joshua Adekoya)

Analyzes text-exported log and hash evidence.

- Reads a text dump of the Security events and extracts 4624/4625 records for `ForensicTest`.
- Builds and sorts an authentication timeline.
- Compares recorded original and modified SHA-256 hashes to detect file content changes.
- Writes a plain-text forensic report to `docs/Forensic_Report.txt`.

## Setup

Requires Python 3.

```bash
pip install -r requirements.txt
```

(`logon_analyzer.py` needs the `python-evtx` library; `main.py` uses only the Python standard library.)

## Usage

### Tadas's tool (raw EVTX)

```bash
python3 src/logon_analyzer.py data/sample_security.evtx --user ForensicTest --utc-offset -6
```

Optional CSV export:

```bash
python3 src/logon_analyzer.py data/sample_security.evtx --user ForensicTest --utc-offset -6 --csv timeline.csv
```

### Josh's tool (text evidence)

```bash
python3 src/main.py
```

This reads `data/Forensic_Logs.txt` and `data/File_Integrity_Evidence.txt` and writes `docs/Forensic_Report.txt`.

## Repository layout

```
.
├── src/
│   ├── logon_analyzer.py        # Tadas: raw EVTX analyzer
│   └── main.py                  # Josh: text log + hash analyzer
├── data/
│   ├── sample_security.evtx     # sample evidence (EVTX)
│   ├── Forensic_Logs.txt        # sample evidence (text log dump)
│   └── File_Integrity_Evidence.txt  # original vs. modified hashes
├── Final_Report.docx.pdf        # written report
├── presentation_slides.pdf      # presentation slides
├── requirements.txt
├── LICENSE
└── README.md
```

## Results

- Evidence SHA-256 verified as unaltered.
- Failed logons (Event ID 4625): 4
- Successful logons (Event ID 4624): 1
- The file modification was confirmed by differing before/after SHA-256 hashes.
- Sushi AI reported only 3 of the 4 failed logons and misclassified the file change as unauthorized.

## Limitations

- Reading the audit policy on Windows required administrator rights.
- Routine service logons (type 5) had to be filtered out to isolate the relevant events.
- Timestamps are stored in UTC in the EVTX and converted to local time (CST, UTC-6) for reporting.
- Hash differences confirm a file changed but do not alone prove the change was unauthorized.

## AI Use Disclosure

An AI assistant was used to help parse the EVTX file, verify event counts and hashes, draft portions of the documentation, and develop the analysis tools. All findings were verified by the authors against the raw forensic evidence.
