from typing import Set, Dict, List
import ast

class TaintAnalyzer:
    def __init__(self):
        self.tainted_variables: Set[str] = set()
        self.taint_flows: Dict[str, List[str]] = {}
        self.sensitive_patterns = {
            'password', 'email', 'ssn', 'credit_card', 'creditcard',
            'address', 'phone', 'dob', 'secret'
        }
        self.sensitive_sinks = {
            'print', 'logging.info', 'logging.debug',
            'json.dumps', 'jsonify', 'redirect'
        }

    def track_taint_flow(self, source: str, sink: str):
        """Track taint flow from source to sink"""
        if source not in self.taint_flows:
            self.taint_flows[source] = []
        self.taint_flows[source].append(sink)

    def is_sensitive_source(self, node: ast.AST) -> bool:
        """Check if a node represents a sensitive data source"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, ast.Name):
            return any(pattern in node.id.lower() for pattern in self.sensitive_patterns)
        return False

    def analyze_node(self, node: ast.AST):
        """Analyze AST node for taint propagation"""
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # Track assignments of sensitive data
                    if self.is_sensitive_source(node.value):
                        self.tainted_variables.add(target.id)
                    # Track variable propagation
                    if isinstance(node.value, ast.Name) and node.value.id in self.tainted_variables:
                        self.tainted_variables.add(target.id)
        
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            
            if func_name in self.sensitive_sinks:
                for arg in node.args:
                    if isinstance(arg, ast.Name) and (arg.id in self.tainted_variables):
                        self.track_taint_flow(arg.id, func_name)

    def analyze_code(self, code: str) -> Dict[str, List[str]]:
        """Analyze Python code for taint flows"""
        self.tainted_variables.clear()
        self.taint_flows.clear()
        
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                self.analyze_node(node)
            return self.taint_flows
        except SyntaxError as e:
            print(f"Syntax error in code: {e}")
            return {}