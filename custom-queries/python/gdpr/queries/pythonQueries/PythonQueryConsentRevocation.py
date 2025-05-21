import os
import re

# Keywords to identify revocation
REVOCATION_PATTERN = re.compile(r"\bconsent\s*=\s*False\b")

# Sensitive data variables
SENSITIVE_VARS = {"email", "ssn", "dob", "password"}

# Functions considered risky
RISKY_USE_PATTERN = re.compile(r"\b(send|send_email|notify)\s*\(")

def analyze_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    revoked_line_nums = set()
    flagged_lines = []

    # Step 1: Find where consent is revoked
    for i, line in enumerate(lines):
        if REVOCATION_PATTERN.search(line):
            revoked_line_nums.add(i)

    # Step 2: After revocation, flag sensitive variable use in risky function calls
    for i, line in enumerate(lines):
        if any(revoked <= i for revoked in revoked_line_nums):
            if RISKY_USE_PATTERN.search(line):
                if any(var in line for var in SENSITIVE_VARS):
                    flagged_lines.append((i + 1, line.strip()))

    return flagged_lines

def scan_directory(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".py"):
            full_path = os.path.join(directory, filename)
            results = analyze_file(full_path)
            if results:
                print(f"\n[!] Issues in {filename}:")
                for line_num, content in results:
                    print(f"  Line {line_num}: {content}")

# Run this to scan your test directory
if __name__ == "__main__":
    scan_directory("test-code")