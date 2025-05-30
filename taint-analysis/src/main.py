import os
import sys
from datetime import datetime
from analyzers.taint_analysis import TaintAnalyzer

def main():
    analyzer = TaintAnalyzer()
    
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        if os.path.exists(filepath):
            results = analyzer.analyze_file(filepath)
        else:
            print(f"Error: File not found - {filepath}")
            return
    else:
        test_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'test-code'
        )
        results = analyzer.analyze_directory(test_dir)
    
    # Generate timestamp for report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f'gdpr_compliance_report_{timestamp}.txt'
    
    # Print and save results with UTF-8 encoding
    summary = analyzer.get_summary()
    print(summary)
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(summary)
    print(f"\nDetailed report saved to: {report_file}")

if __name__ == "__main__":
    main()