
from pathlib import Path
from datetime import datetime
import re

# Find the main project folder
project_folder = Path(__file__).resolve().parent.parent

# Locations of the evidence files
log_file = project_folder / "data" / "Forensic_Logs.txt"
hash_file = project_folder / "data" / "File_Integrity_Evidence.txt"
report_file = project_folder / "docs" / "Forensic_Report.txt"

# Create the report folder if it does not exist
report_file.parent.mkdir(parents=True, exist_ok=True)

print("\n===== WINDOWS FORENSIC LOG ANALYZER =====")

# ----------------------------------------
# PART 1: WINDOWS SECURITY LOG ANALYSIS
# ----------------------------------------

try:
    logs = log_file.read_text(
        encoding="utf-8-sig", errors="replace"
    )
except FileNotFoundError:
    print("ERROR: Forensic_Logs.txt was not found.")
    raise SystemExit(1)

# Split the text into individual Windows events
events = re.split(
    r"(?=^\s*TimeCreated\s*:)",
    logs,
    flags=re.MULTILINE
)

failed_logins = []
successful_logins = []

for event in events:

    event_id = re.search(
        r"^\s*Id\s*:\s*(4624|4625)\b",
        event,
        re.MULTILINE
    )

    timestamp = re.search(
        r"^\s*TimeCreated\s*:\s*(.+)",
        event,
        re.MULTILINE
    )

    # Skip entries without an event ID or timestamp
    if event_id is None or timestamp is None:
        continue

    # Only analyze our test account
    if not re.search(
        r"Account Name:\s*ForensicTest\b",
        event,
        re.IGNORECASE
    ):
        continue

    record = (
        timestamp.group(1).strip(),
        event_id.group(1)
    )

    if event_id.group(1) == "4625":
        failed_logins.append(record)
    else:
        successful_logins.append(record)

print("Account: ForensicTest")
print("Failed logins (4625):", len(failed_logins))
print("Successful logins (4624):", len(successful_logins))

# Combine and sort all authentication events
all_events = failed_logins + successful_logins

try:
    all_events.sort(
        key=lambda event: datetime.strptime(
            event[0],
            "%m/%d/%Y %I:%M:%S %p"
        )
    )
except ValueError:
    print("WARNING: Some timestamps could not be sorted.")

print("\n===== AUTHENTICATION EVENTS =====")

for timestamp, event_id in all_events:
    result = "FAILED" if event_id == "4625" else "SUCCESS"
    print(timestamp, "| Event", event_id, "|", result)

# ----------------------------------------
# PART 2: FILE INTEGRITY ANALYSIS
# ----------------------------------------

print("\n===== FILE INTEGRITY ANALYSIS =====")

hash_finding = "File integrity evidence unavailable."
original_hash = "Not available"
modified_hash = "Not available"

try:
    hash_text = hash_file.read_text(
        encoding="utf-8-sig", errors="replace"
    )

    # Find the original SHA-256 value
    original_match = re.search(
        r"Original SHA-256:\s*([a-fA-F0-9]+)",
        hash_text,
        re.IGNORECASE
    )

    # Find the modified SHA-256 value
    modified_match = re.search(
        r"Modified SHA-256:\s*([a-fA-F0-9]+)",
        hash_text,
        re.IGNORECASE
    )

    if original_match and modified_match:

        original_hash = original_match.group(1)
        modified_hash = modified_match.group(1)

        print("Original hash length:", len(original_hash))
        print("Modified hash length:", len(modified_hash))

        # SHA-256 hashes must contain 64 hexadecimal characters
        if len(original_hash) != 64 or len(modified_hash) != 64:
            hash_finding = (
                "Invalid SHA-256 evidence: "
                "Both hashes must contain 64 characters."
            )

        elif original_hash.lower() == modified_hash.lower():
            hash_finding = (
                "The SHA-256 hashes match. "
                "No content difference was detected."
            )

        else:
            hash_finding = (
                "The SHA-256 hashes differ. "
                "This indicates the file contents changed."
            )

        print("Original SHA-256:", original_hash)
        print("Modified SHA-256:", modified_hash)
        print("Finding:", hash_finding)

    else:
        hash_finding = (
            "ERROR: Could not find both SHA-256 hashes."
        )
        print(hash_finding)

except FileNotFoundError:
    print("ERROR: File_Integrity_Evidence.txt was not found.")

print(
    "Note: Hash differences alone do not prove "
    "unauthorized modification."
)

# ----------------------------------------
# PART 3: GENERATE FORENSIC REPORT
# ----------------------------------------

with open(report_file, "w", encoding="utf-8") as report:

    report.write("WINDOWS FORENSIC INVESTIGATION REPORT\n")
    report.write("=====================================\n\n")

    report.write("AUTHENTICATION ANALYSIS\n")
    report.write("-----------------------\n")

    report.write("Account: ForensicTest\n")
    report.write(
        "Failed logins (4625): " + str(len(failed_logins)) + "\n"
    )
    report.write(
        "Successful logins (4624): "
        + str(len(successful_logins)) + "\n"
    )

    report.write("\nAUTHENTICATION TIMELINE\n")
    report.write("-----------------------\n")

    for timestamp, event_id in all_events:
        result = "FAILED" if event_id == "4625" else "SUCCESS"

        report.write(
            timestamp + " | Event " + event_id
            + " | " + result + "\n"
        )

    report.write("\nAUTHENTICATION FINDINGS\n")
    report.write("-----------------------\n")

    if failed_logins and successful_logins:
        report.write(
            "Failed and successful logins were detected.\n"
        )
        report.write(
            "Review the timeline for possible password guessing.\n"
        )
    else:
        report.write(
            "Insufficient evidence for a failed-to-successful "
            "login pattern.\n"
        )

    report.write(
        "Authentication events alone do not prove "
        "unauthorized access.\n"
    )

    report.write("\nFILE INTEGRITY ANALYSIS\n")
    report.write("-----------------------\n")

    report.write("Original SHA-256: " + original_hash + "\n")
    report.write("Modified SHA-256: " + modified_hash + "\n")
    report.write("Finding: " + hash_finding + "\n")

    report.write(
        "Hash differences alone do not prove "
        "unauthorized modification.\n"
    )

    report.write("\nCONCLUSION\n")
    report.write("----------\n")

    report.write(
        "This tool analyzes Windows authentication events "
        "and compares recorded SHA-256 hashes.\n"
    )

    report.write(
        "Findings must be verified against original "
        "forensic evidence.\n"
    )

print("\nReport saved to:", report_file)
print("\nAnalysis complete.")
