import os
import re

# Regex patterns
REVOCATION_PATTERN = re.compile(r"\bconsent\s*=\s*False\b")
CONSENT_BLOCK_PATTERN = re.compile(r"^\s*if\s+consent\s*:")
RISKY_USE_PATTERN = re.compile(r"\b(send|send_email|notify)\s*\(")
WRITE_PATTERN = re.compile(r"\.write(?:lines)?\s*\(")
CARD_PATTERN = re.compile(r'"\d{4}-\d{4}-\d{4}-\d{4}"')
SSN_PATTERN = re.compile(r'"\d{3}-\d{2}-\d{4}"')
URL_PATTERN = re.compile(r'"https?://[^"]*"\s*\+\s*(?!hash_\w+\()(\w+)')
SQL_INJECTION_PATTERN = re.compile(r'\bSELECT\b.*\bFROM\b.*\+.*\b\w+\b', re.IGNORECASE)
RAISE_SENSITIVE_PATTERN = re.compile(r'raise\s+\w+\s*\(.*\+\s*\w+\s*\)', re.IGNORECASE)
LOCAL_STORAGE_PATTERN = re.compile(
    r'\b(?:localStorage|sessionStorage)\s*(?:\.setItem\s*\(|\[\s*["\']\w+["\']\s*\]\s*=\s*)',
    re.IGNORECASE
)

# Sensitive data variable names
SENSITIVE_VARS = {"email", "ssn", "dob", "password"}


def analyze_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    flagged_lines = []
    revoked_line_nums = set()
    inside_consent_block = False
    indent_level = None

    # --- Consent Revocation Detection ---
    for i, line in enumerate(lines):
        if REVOCATION_PATTERN.search(line):
            revoked_line_nums.add(i)

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track consent block state by indentation
        if CONSENT_BLOCK_PATTERN.match(line):
            inside_consent_block = True
            indent_level = len(line) - len(line.lstrip())
            continue

        # Exit consent block if indentation decreases
        if inside_consent_block:
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= indent_level and stripped != "":
                inside_consent_block = False

        # Skip risky ops inside consent block
        if inside_consent_block:
            continue

        # Consent revoked? Flag risky usage
        if any(revoked <= i for revoked in revoked_line_nums):
            if RISKY_USE_PATTERN.search(line) and any(var in line for var in SENSITIVE_VARS):
                flagged_lines.append((filepath, i + 1, "[Consent Revoked] " + stripped))

    # --- Card Number Detection (skip if wrapped in hash or other function) ---
    for i, line in enumerate(lines):
        if CARD_PATTERN.search(line):
            if not re.search(r'\w+\s*\(\s*"\d{4}-\d{4}-\d{4}-\d{4}"\s*\)', line):
                flagged_lines.append((filepath, i + 1, "[Card Pattern] " + line.strip()))

    # --- SSN Detection (skip if wrapped in hash or other function) ---
    for i, line in enumerate(lines):
        if SSN_PATTERN.search(line):
            if not re.search(r'\w+\s*\(\s*"\d{3}-\d{2}-\d{4}"\s*\)', line):
                flagged_lines.append((filepath, i + 1, "[SSN Pattern] " + line.strip()))

    # --- Sensitive Write Detection ---
    for i, line in enumerate(lines):
        if WRITE_PATTERN.search(line) and any(var in line for var in SENSITIVE_VARS):
            flagged_lines.append((filepath, i + 1, "[Sensitive Write] " + line.strip()))

    # --- Sensitive Data Embedded in URL Detection (not hashed) ---
    for i, line in enumerate(lines):
        match = URL_PATTERN.search(line)
        if match and match.group(1) in SENSITIVE_VARS:
            flagged_lines.append((filepath, i + 1, "[Sensitive URL Embedding] " + line.strip()))
            
    # --- SQL Injection Detection ---
    for i, line in enumerate(lines):
        if SQL_INJECTION_PATTERN.search(line):
            flagged_lines.append((filepath, i + 1, "[SQL Injection Risk] " + line.strip()))
            
    # --- Sensitive Data in Exception Messages ---
    for i, line in enumerate(lines):
        if RAISE_SENSITIVE_PATTERN.search(line):
            flagged_lines.append((filepath, i + 1, "[Sensitive in Exception] " + line.strip()))
            
    # --- Local Storage Usage Detection ---
    for i, line in enumerate(lines):
        if LOCAL_STORAGE_PATTERN.search(line) and any(var in line for var in SENSITIVE_VARS):
            flagged_lines.append((filepath, i + 1, "[Local Storage Usage] " + line.strip()))


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
