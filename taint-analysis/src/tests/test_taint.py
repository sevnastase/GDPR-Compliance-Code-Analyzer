import pytest
from src.analyzers.taint_analysis import TaintAnalyzer

def test_sensitive_source_detection():
    analyzer = TaintAnalyzer()
    code = """
    password = "secret123"
    print(password)
    """
    flows = analyzer.analyze_code(code)
    assert "password" in flows
    assert "print" in flows["password"]

def test_taint_propagation():
    analyzer = TaintAnalyzer()
    code = """
    email = request.form['email']
    user_data = email
    json.dumps(user_data)
    """
    flows = analyzer.analyze_code(code)
    assert "email" in flows
    assert "json.dumps" in flows["email"]

def test_multiple_sinks():
    analyzer = TaintAnalyzer()
    code = """
    ssn = input("Enter SSN: ")
    print(ssn)
    logging.info(ssn)
    """
    flows = analyzer.analyze_code(code)
    assert "ssn" in flows
    assert len(flows["ssn"]) == 2