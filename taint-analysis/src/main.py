from analyzers.taint_analysis import TaintAnalyzer
import logging

def main():
    # Configure basic logging
    logging.basicConfig(level=logging.INFO)
    
    test_cases = [
        # Test case 1: Direct sensitive data leak
        """
password = "secret123"
print(password)
logging.info(password)
""",
        # Test case 2: Data flow through variable
        """
email = "user@example.com"
user_data = email
print(user_data)
""",
        # Test case 3: Multiple sinks with credit card
        """
credit_card = "1234-5678-9012-3456"
card_info = credit_card
print(card_info)
logging.info(card_info)
"""
    ]
    
    print("Running taint analysis...")
    for i, test_code in enumerate(test_cases, 1):
        analyzer = TaintAnalyzer()  # Reset analyzer for each test
        print(f"\nTest Case {i}:")
        print("-" * 40)
        print(f"Code:\n{test_code}")
        flows = analyzer.analyze_code(test_code)
        if flows:
            print(f"Detected taint flows:")
            for source, sinks in flows.items():
                print(f"  {source} -> {', '.join(sinks)}")
        else:
            print("No taint flows detected")
        print("-" * 40)

if __name__ == "__main__":
    main()