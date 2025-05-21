import re

def detect_card_patterns(file_path):
    # Regex pattern for credit card–like format: 4 groups of 4 digits separated by hyphens
    card_pattern = re.compile(r'"\d{4}-\d{4}-\d{4}-\d{4}"')

    with open(file_path, 'r', encoding='utf-8') as f:
        for line_number, line in enumerate(f, start=1):
            if card_pattern.search(line):
                print(f"[!] Potential card number found on line {line_number}: {line.strip()}")

# Example usage
if __name__ == "__main__":
    detect_card_patterns("test-code/insecure16.py")