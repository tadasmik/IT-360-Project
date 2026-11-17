#!/usr/bin/env python3
"""
logon_analyzer.py - Windows Security EVTX logon forensic analyzer.

Parses a Windows Security event log (.evtx), extracts authentication events
(Event ID 4624 successful logon, 4625 failed logon), verifies the evidence
file's SHA-256 hash, and produces an independent incident timeline.

Built for IT 360 Final Project:
"SIEM Detection and Forensic Analysis of a Simulated Account Compromise".

The tool exists to corroborate automated/AI SIEM output against the raw logs.
In our incident the AI tool under-counted the failed logons; running the raw
EVTX through this parser gives the ground-truth event count and timeline.
"""

import argparse
import csv
import hashlib
import sys
from collections import Counter
from datetime import datetime, timedelta

try:
    from Evtx.Evtx import Evtx
except ImportError:
    sys.exit("Missing dependency. Run: pip install -r requirements.txt")

import xml.etree.ElementTree as ET

# Windows event XML namespace
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Logon-related event IDs we care about
FAILED_LOGON = "4625"
SUCCESS_LOGON = "4624"

# Common failure sub-status codes, decoded to plain English
SUBSTATUS = {
    "0xc000006a": "Incorrect password",
    "0xc0000064": "Username does not exist",
    "0xc0000234": "Account locked out",
    "0xc0000072": "Account disabled",
    "0xc000006f": "Logon outside allowed hours",
    "0xc0000070": "Logon from unauthorized workstation",
}

# Logon type codes
LOGON_TYPES = {
    "2": "Interactive (local keyboard)",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def sha256_file(path):
    """Return the SHA-256 hex digest of a file, read in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_events(evtx_path, utc_offset_hours=0):
    """Yield one dict per 4624/4625 record found in the EVTX file."""
    with Evtx(evtx_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except Exception:
                # Skip records that fail to parse rather than crashing
                continue

            system = root.find(NS + "System")
            if system is None:
                continue
            eid = system.findtext(NS + "EventID")
            if eid not in (FAILED_LOGON, SUCCESS_LOGON):
                continue

            # Event data fields are name/value pairs
            fields = {}
            edata = root.find(NS + "EventData")
            if edata is not None:
                for d in edata.findall(NS + "Data"):
                    fields[d.get("Name")] = d.text

            tc = system.find(NS + "TimeCreated")
            raw_time = tc.get("SystemTime") if tc is not None else ""
            local_time = raw_time
            if raw_time:
                try:
                    dt = datetime.fromisoformat(raw_time)
                    dt = dt + timedelta(hours=utc_offset_hours)
                    local_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

            substatus = (fields.get("SubStatus") or "").lower()
            yield {
                "time": local_time,
                "event_id": eid,
                "result": "SUCCESS" if eid == SUCCESS_LOGON else "FAILED",
                "user": fields.get("TargetUserName", ""),
                "domain": fields.get("TargetDomainName", ""),
                "logon_type": fields.get("LogonType", ""),
                "logon_type_desc": LOGON_TYPES.get(fields.get("LogonType", ""), "Unknown"),
                "source_ip": fields.get("IpAddress", ""),
                "workstation": fields.get("WorkstationName", ""),
                "substatus": substatus,
                "reason": SUBSTATUS.get(substatus, "") if eid == FAILED_LOGON else "",
            }


def main():
    ap = argparse.ArgumentParser(description="Windows EVTX logon forensic analyzer")
    ap.add_argument("evtx", help="Path to the .evtx Security log")
    ap.add_argument("--user", help="Only show events for this account name")
    ap.add_argument("--csv", help="Write the timeline to this CSV file")
    ap.add_argument("--utc-offset", type=int, default=0,
                    help="Hours to add to UTC for local time (e.g. -6 for CST)")
    args = ap.parse_args()

    print("=" * 60)
    print("Windows EVTX Logon Forensic Analyzer")
    print("=" * 60)

    # 1. Evidence integrity
    digest = sha256_file(args.evtx)
    print(f"Evidence file : {args.evtx}")
    print(f"SHA-256       : {digest}")
    print("-" * 60)

    # 2. Parse
    events = list(parse_events(args.evtx, args.utc_offset))
    if args.user:
        events = [e for e in events if e["user"].lower() == args.user.lower()]
    events.sort(key=lambda e: e["time"])

    # 3. Summary counts
    counts = Counter(e["result"] for e in events)
    print(f"Failed logons (4625)  : {counts.get('FAILED', 0)}")
    print(f"Successful logons (4624): {counts.get('SUCCESS', 0)}")
    print("-" * 60)

    # 4. Timeline
    print("Incident timeline:")
    for e in events:
        line = (f"  {e['time']}  [{e['event_id']} {e['result']}]  "
                f"user={e['domain']}\\{e['user']}  "
                f"type={e['logon_type']}({e['logon_type_desc']})  "
                f"src={e['source_ip']}")
        if e["reason"]:
            line += f"  reason={e['reason']}"
        print(line)

    # 5. Optional CSV for the report
    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(events[0].keys()) if events else [])
            writer.writeheader()
            writer.writerows(events)
        print("-" * 60)
        print(f"Timeline written to {args.csv}")


if __name__ == "__main__":
    main()
