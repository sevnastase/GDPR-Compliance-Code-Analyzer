import os
import re

# Regex patterns
REVOCATION_PATTERN = re.compile(r"\bconsent\s*=\s*False\b")
RISKY_USE_PATTERN = re.compile(r"\b(send|send_email|notify)\s*\(")
WRITE_PATTERN = re.compile(r"\.write(?:lines)?\s*\(")
CARD_PATTERN = re.compile(r'"\d{4}-\d{4}-\d{4}-\d{4}"')
SSN_PATTERN = re.compile(r'"\d{3}-\d{2}-\d{4}"')

# Sensitive data variable names
SENSITIVE_VARS = {"email", "ssn", "dob", "password"}


def analyze_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    revoked_line_nums = set()
    flagged_lines = []

    # --- Consent Revocation Detection ---
    for i, line in enumerate(lines):
        if REVOCATION_PATTERN.search(line):
            revoked_line_nums.add(i)

    for i, line in enumerate(lines):
        if any(revoked <= i for revoked in revoked_line_nums):
            if RISKY_USE_PATTERN.search(line) and any(var in line for var in SENSITIVE_VARS):
                flagged_lines.append((filepath, i + 1, "[Consent Revoked] " + line.strip()))

    # --- Card Number Detection ---
    for i, line in enumerate(lines):
        if CARD_PATTERN.search(line):
            flagged_lines.append((filepath, i + 1, "[Card Pattern] " + line.strip()))

    # --- SSN Detection ---
    for i, line in enumerate(lines):
        if SSN_PATTERN.search(line):
            flagged_lines.append((filepath, i + 1, "[SSN Pattern] " + line.strip()))

    # --- Sensitive Write Detection ---
    for i, line in enumerate(lines):
        if WRITE_PATTERN.search(line) and any(var in line for var in SENSITIVE_VARS):
            flagged_lines.append((filepath, i + 1, "[Sensitive Write] " + line.strip()))

    return flagged_lines


def scan_directory(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".py"):
            full_path = os.path.join(directory, filename)
            results = analyze_file(full_path)
            if results:
                print(f"\n[!] Issues in {filename}:")
                for file, line_num, message in results:
                    print(f"  Line {line_num}: {message}")


if __name__ == "__main__":
    scan_directory("test-code")
