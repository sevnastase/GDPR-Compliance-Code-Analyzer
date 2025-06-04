import ast
from typing import Set, Dict, List
import os
import glob
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.gdpr_rules import (
    GDPR_SENSITIVE_DATA, 
    GDPR_REQUIREMENTS, 
    GDPR_DB_OPERATIONS,
    DATA_TRANSFER_PATTERNS,
    COMMON_FRAMEWORKS
)

class GDPRCompliance:
    def __init__(self):
        self.violations: List[Dict] = []
        self.compliance_status: Dict = {
            'has_consent': False,
            'has_encryption': False,
            'has_retention': False,
            'has_minimization': True
        }
    
    def add_violation(self, violation_type: str, details: str, line_no: int, severity: str):
        self.violations.append({
            'type': violation_type,
            'details': details,
            'line': line_no,
            'severity': severity
        })

class TaintAnalyzer:
    def __init__(self):
        self.tainted_variables: Set[str] = set()
        self.taint_flows: Dict[str, List[Dict]] = {}  # Changed to List[Dict] for structured flow data
        self.gdpr = GDPRCompliance()
        self.results: Dict[str, Dict] = {}
        self.sensitive_patterns = set().union(*[data['patterns'] for data in GDPR_SENSITIVE_DATA.values()])
        self.sensitive_sinks = {
            'print', 'logging.info', 'logging.debug', 'logging.error',
            'json.dumps', 'jsonify', 'redirect', 'execute', 'executemany'
        }

    def is_data_collection(self, node: ast.Call) -> bool:
        """Check if node represents data collection operation"""
        if isinstance(node.func, ast.Name):
            collection_functions = {'input', 'get', 'read', 'load', 'loads'}
            return node.func.id in collection_functions
        elif isinstance(node.func, ast.Attribute):
            collection_methods = {'get', 'read', 'readline', 'load', 'loads'}
            return node.func.attr in collection_methods
        return False

    def analyze_node(self, node: ast.AST, filename: str):
        """Analyze AST node for taint propagation and GDPR compliance"""
        for child in ast.iter_child_nodes(node):
            setattr(child, 'parent', node)

        if isinstance(node, ast.Call):
            self.check_call_node(node, filename)
        elif isinstance(node, ast.Assign):
            self.check_assignment_node(node, filename)
        elif isinstance(node, ast.ClassDef):
            self.check_class_node(node, filename)
        elif isinstance(node, ast.FunctionDef):
            self.check_function_node(node, filename)

    def check_call_node(self, node: ast.Call, filename: str):
        """Check call nodes for GDPR violations"""
        # Check for data collection without consent
        if self.is_data_collection(node):
            if not self.has_consent(node):
                self.gdpr.add_violation(
                    'missing_consent',
                    'Collecting personal data without explicit consent',
                    node.lineno,
                    'high'
                )

            # Check if sensitive data is being collected
            if self.contains_sensitive_data(node):
                if not self.has_encryption(node):
                    self.gdpr.add_violation(
                        'unprotected_sensitive_data',
                        'Handling sensitive data without encryption',
                        node.lineno,
                        'critical'
                    )

        # Check database operations
        if self.is_db_operation(node):
            self.check_db_operation(node)

        # Check data transfer operations
        self.check_data_transfer(node, filename)

        # Check framework-specific compliance
        self.check_framework_specific(node)

    def check_assignment_node(self, node: ast.Assign, filename: str):
        """Check assignment nodes for GDPR violations"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                if self.is_sensitive_source(node.value):
                    self.tainted_variables.add(target.id)
                    
                    # Only mark as non-compliant if there's no protection
                    if not self.has_encryption(node):
                        self.gdpr.compliance_status['has_encryption'] = False
                        self.gdpr.add_violation(
                            'unprotected_storage',
                            f'Storing sensitive data in variable {target.id} without protection',
                            node.lineno,
                            'high'
                        )
                
                if not self.has_retention_policy(node):
                    self.gdpr.compliance_status['has_retention'] = False
                    self.gdpr.add_violation(
                        'missing_retention',
                        f'No retention policy for sensitive data in {target.id}',
                        node.lineno,
                        'medium'
                    )
    def is_db_operation(self, node: ast.Call) -> bool:
        """Check if the call is a database operation"""
        call_name = self.get_call_name(node)
        return (
            any(op in call_name.lower() for op in GDPR_DB_OPERATIONS['storage']) or
            any(op in call_name.lower() for op in GDPR_DB_OPERATIONS['retrieval'])
        )
    
    def contains_sensitive_data(self, node: ast.AST) -> bool:
        """Check if node contains sensitive data patterns"""
        if isinstance(node, ast.Call):
            for arg in node.args:
                if self.is_sensitive_source(arg):
                    return True
            for keyword in node.keywords:
                if self.is_sensitive_source(keyword.value):
                    return True
        return False

    def check_db_operation(self, node: ast.Call):
        """Check database operations for GDPR compliance"""
        if self.contains_sensitive_data(node):
            if not self.has_consent(node):
                self.gdpr.add_violation(
                    'unauthorized_db_access',
                    'Database operation with sensitive data without consent',
                    node.lineno,
                    'high'
                )
            if not self.has_encryption(node):
                self.gdpr.add_violation(
                    'unencrypted_db_operation',
                    'Unencrypted database operation with sensitive data',
                    node.lineno,
                    'critical'
                )
        
    def is_storage_operation(self, node: ast.Call) -> bool:
        """Check if operation involves data storage"""
        storage_patterns = {
            'save', 'store', 'insert', 'write', 'update', 
            'create', 'add', 'put', 'set', 'push'
        }
        if isinstance(node.func, ast.Name):
            return node.func.id in storage_patterns
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr in storage_patterns
        return False

    def has_retention_policy(self, node: ast.AST) -> bool:
        """Check if data has retention policy"""
        retention_patterns = {'retention', 'expire', 'timeout', 'ttl', 'delete_after'}
        
        # Look for retention policy in variable annotations or comments
        if hasattr(node, 'lineno'):
            tree = ast.walk(node)
            for n in tree:
                if isinstance(n, ast.AnnAssign) and hasattr(n, 'annotation'):
                    annotation_str = ast.unparse(n.annotation)
                    if any(pattern in annotation_str.lower() for pattern in retention_patterns):
                        return True
        return False

    def has_consent(self, node: ast.AST) -> bool:
        """Check if proper consent is obtained for data processing"""
        # Start with non-compliant status
        self.gdpr.compliance_status['has_consent'] = False
        
        # Get all required patterns and functions
        consent_functions = set(GDPR_REQUIREMENTS['consent']['functions'])
        consent_patterns = set(GDPR_REQUIREMENTS['consent']['required_patterns'])
        
        # Find root node
        root = node
        while hasattr(root, 'parent'):
            root = getattr(root, 'parent')
        
        class ConsentVisitor(ast.NodeVisitor):
            def __init__(self):
                self.found_consent = False
                self.consent_before_usage = False
                self.data_usage_line = 0
                self.last_consent_line = 0
                
            def visit_Call(self, node):
                # Track data usage line
                if isinstance(node, ast.Call) and hasattr(node, 'lineno'):
                    self.data_usage_line = node.lineno
                    
                # Check function calls for consent
                if isinstance(node.func, ast.Name):
                    if (node.func.id in consent_functions or 
                        any(pattern in node.func.id.lower() for pattern in consent_patterns)):
                        self.found_consent = True
                        if hasattr(node, 'lineno'):
                            self.last_consent_line = node.lineno
                            # Check if consent is obtained before data usage
                            if self.last_consent_line < self.data_usage_line:
                                self.consent_before_usage = True
                        
                elif isinstance(node.func, ast.Attribute):
                    if any(pattern in node.func.attr.lower() for pattern in consent_patterns):
                        self.found_consent = True
                        if hasattr(node, 'lineno'):
                            self.last_consent_line = node.lineno
                            if self.last_consent_line < self.data_usage_line:
                                self.consent_before_usage = True
                        
                self.generic_visit(node)
                
            def visit_Decorator(self, node):
                if isinstance(node, ast.Name):
                    if any(pattern in node.id.lower() for pattern in consent_patterns):
                        self.found_consent = True
                        self.consent_before_usage = True
                self.generic_visit(node)
                
            def visit_With(self, node):
                # Check context managers for consent handling
                if isinstance(node.items[0].context_expr, ast.Call):
                    if any(pattern in self.get_call_name(node.items[0].context_expr).lower() 
                          for pattern in consent_patterns):
                        self.found_consent = True
                        self.consent_before_usage = True
                self.generic_visit(node)

        visitor = ConsentVisitor()
        visitor.visit(root)
        
        # Update compliance status based on proper consent implementation
        has_valid_consent = visitor.found_consent and visitor.consent_before_usage
        self.gdpr.compliance_status['has_consent'] = has_valid_consent
        
        return has_valid_consent

    def get_call_name(self, node: ast.Call) -> str:
        """Extract callable name from Call node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ""

    # ... existing code for analyze_file, analyze_directory, and get_summary ...

    def check_gdpr_compliance(self, node: ast.Call):
        """Check for GDPR compliance violations"""
        if self.is_data_collection(node):
            if not self.has_consent(node):
                self.gdpr.add_violation(
                    'missing_consent',
                    'Collecting personal data without explicit consent',
                    node.lineno,
                    'high'
                )
            
            # Check for encryption when storing data
            if self.is_storage_operation(node) and not self.has_encryption(node):
                self.gdpr.add_violation(
                    'unencrypted_storage',
                    'Storing sensitive data without encryption',
                    node.lineno,
                    'high'
                )


    def has_encryption(self, node: ast.Call) -> bool:
        """Check if data is being encrypted"""
        encryption_patterns = set(GDPR_REQUIREMENTS['security']['required_patterns'])
        current = node
        while hasattr(current, 'parent'):
            if isinstance(current, ast.Call):
                if self.get_call_name(current).split('.')[-1] in encryption_patterns:
                    return True
            current = getattr(current, 'parent', None)
        return False
    
    def analyze_directory(self, directory: str) -> Dict[str, Dict]:
        """Analyze all Python files in a directory for GDPR compliance"""
        self.results.clear()
        
        try:
            # Find all Python files in the directory
            python_files = glob.glob(os.path.join(directory, "**/*.py"), recursive=True)
            
            if not python_files:
                print(f"No Python files found in {directory}")
                return {}
            
            # Analyze each file
            for filepath in python_files:
                print(f"Analyzing: {os.path.basename(filepath)}")
                result = self.analyze_file(filepath)
                self.results[os.path.basename(filepath)] = result
            
            return self.results
            
        except Exception as e:
            print(f"Error analyzing directory {directory}: {str(e)}")
            return {'error': str(e)}
    
    def analyze_file(self, filepath: str) -> Dict:
        """Analyze a single Python file for GDPR compliance"""
        self.tainted_variables.clear()
        self.gdpr = GDPRCompliance()
        
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                tree = ast.parse(file.read())
                filename = os.path.basename(filepath)
                
                # Reset compliance status for each file
                self.gdpr.compliance_status = {
                    'has_consent': True,  # Start with compliant and mark as False if violations found
                    'has_encryption': True,
                    'has_retention': True,
                    'has_minimization': True
                }
                
                # Check imports for security features
                self.check_security_imports(tree)
                
                # Analyze nodes
                for node in ast.walk(tree):
                    self.analyze_node(node, filename)
                
                return {
                    'filepath': filepath,
                    'flows': self.taint_flows.get(filename, []),
                    'violations': self.gdpr.violations,
                    'compliance': self.gdpr.compliance_status
                }
        except Exception as e:
            return {'filepath': filepath, 'error': str(e)}

    def check_security_imports(self, tree: ast.AST):
        """Check for security-related imports"""
        security_modules = {
            'cryptography', 'ssl', 'hashlib', 'secrets',
            'django.middleware.security', 'flask_security',
            'sqlalchemy.crypto', 'werkzeug.security'
        }
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module_name = node.names[0].name.split('.')[0]
                if module_name in security_modules:
                    self.gdpr.compliance_status['has_encryption'] = True

    def get_summary(self) -> str:
        """Generate a detailed compliance report"""
        summary = ["GDPR Compliance Analysis Summary", "=" * 30, ""]
        
        for filename, result in self.results.items():
            summary.append(f"\nFile: {filename}")
            summary.append("-" * (len(filename) + 6))
            
            if 'error' in result:
                summary.append(f"Error: {result['error']}")
                continue
            
            # GDPR Violations
            violations = result.get('violations', [])
            if violations:
                summary.append("\nGDPR Violations Found:")
                for v in violations:
                    summary.append(f"     Line {v['line']}: {v['type']}")
                    summary.append(f"     Details: {v['details']}")
                    summary.append(f"     Severity: {v['severity']}")
            else:
                summary.append("\n No GDPR violations detected")
            
            # Taint Flows
            flows = result.get('flows', [])
            if flows:
                summary.append("\nTaint Flows Detected:")
                for flow in flows:
                    summary.append(f"  Line {flow['line']}: {flow['source']} -> {flow['sink']}")
            
            # Compliance Status
            status = result.get('compliance', {})
            summary.append("\nCompliance Status:")
            for key, value in status.items():
                icon = "Looks Good for" if value else "Not Compliant for"
                summary.append(f"  {icon} {key.replace('_', ' ').title()}")
            
            summary.append("\n" + "-" * 50)
        
        return "\n".join(summary)
    
    def is_sensitive_source(self, node: ast.AST) -> bool:
        """Check if a node represents a sensitive data source"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return any(pattern in str(node.value).lower() for pattern in self.sensitive_patterns)
        if isinstance(node, ast.Name):
            return any(pattern in node.id.lower() for pattern in self.sensitive_patterns)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                sensitive_functions = {'input', 'request.form.get', 'request.args.get'}
                return node.func.id in sensitive_functions
            elif isinstance(node.func, ast.Attribute):
                sensitive_attributes = {'form', 'args', 'cookies', 'headers'}
                return node.func.attr in sensitive_attributes
        return False

    def track_taint_flow(self, source: str, sink: str, filename: str, line_no: int):
        """Track taint flow from source to sink"""
        if filename not in self.taint_flows:
            self.taint_flows[filename] = []
        self.taint_flows[filename].append({
            'source': source,
            'sink': sink,
            'line': line_no
        })    
        
    def check_function_node(self, node: ast.FunctionDef, filename: str):
        """Analyze function definitions for GDPR compliance"""
        # Check function parameters for sensitive data
        for arg in node.args.args:
            if any(pattern in arg.arg.lower() for pattern in self.sensitive_patterns):
                # Check if function has proper data protection
                if not self.has_encryption(node):
                    self.gdpr.add_violation(
                        'unprotected_parameter',
                        f'Function parameter {arg.arg} contains sensitive data without protection',
                        node.lineno,
                        'medium'
                    )
        
        # Check function decorators for security measures
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id in {'requires_consent', 'encrypted', 'secure'}:
                    self.gdpr.compliance_status['has_encryption'] = True
                if decorator.id in {'check_consent', 'requires_permission'}:
                    self.gdpr.compliance_status['has_consent'] = True

    def check_class_node(self, node: ast.ClassDef, filename: str):
        """Analyze class definitions for GDPR compliance"""
        # Check class attributes for sensitive data
        for item in node.body:
            if isinstance(item, ast.AnnAssign):
                if hasattr(item, 'target') and isinstance(item.target, ast.Name):
                    if any(pattern in item.target.id.lower() for pattern in self.sensitive_patterns):
                        # Check for data protection attributes
                        if not self.has_protection_attributes(node):
                            self.gdpr.add_violation(
                                'unprotected_class_data',
                                f'Class {node.name} contains sensitive data without protection',
                                node.lineno,
                                'high'
                            )
        
        # Check class decorators for GDPR compliance
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id in {'encrypted_data', 'secure_storage'}:
                    self.gdpr.compliance_status['has_encryption'] = True
                if decorator.id in {'requires_consent', 'gdpr_compliant'}:
                    self.gdpr.compliance_status['has_consent'] = True

    def has_protection_attributes(self, node: ast.ClassDef) -> bool:
        """Check if class has data protection attributes"""
        protection_decorators = {'encrypted_data', 'secure_storage', 'gdpr_compliant'}
        return any(
            isinstance(d, ast.Name) and d.id in protection_decorators
            for d in node.decorator_list
        )

    def check_data_transfer(self, node: ast.Call, filename: str):
        """Check data transfer operations for GDPR compliance"""
        call_name = self.get_call_name(node)
        if any(pattern in call_name for pattern in DATA_TRANSFER_PATTERNS):
            if self.contains_sensitive_data(node):
                if not self.has_consent(node):
                    self.gdpr.add_violation(
                        'unauthorized_data_transfer',
                        'Transferring sensitive data without consent',
                        node.lineno,
                        'critical'
                    )
                if not self.has_encryption(node):
                    self.gdpr.add_violation(
                        'unencrypted_transfer',
                        'Transferring sensitive data without encryption',
                        node.lineno,
                        'critical'
                    )

    def check_framework_specific(self, node: ast.Call):
        """Check framework-specific GDPR compliance"""
        call_name = self.get_call_name(node)
        for framework, patterns in COMMON_FRAMEWORKS.items():
            if any(pattern in call_name for pattern in patterns):
                if not self.has_security_middleware(node):
                    self.gdpr.add_violation(
                        f'insecure_{framework}_usage',
                        f'Using {framework} without proper security middleware',
                        node.lineno,
                        'high'
                    )

    def has_security_middleware(self, node: ast.Call) -> bool:
        """Check if proper security middleware is in place"""
        # Look for security middleware in imports and configurations
        root = node
        while hasattr(root, 'parent'):
            root = getattr(root, 'parent')
        
        for n in ast.walk(root):
            if isinstance(n, ast.Import) or isinstance(n, ast.ImportFrom):
                for name in n.names:
                    if any(pattern in name.name for pattern in [
                        'csrf', 'security', 'protection', 'middleware',
                        'encryption', 'ssl', 'tls'
                    ]):
                        return True
        return False

    def check_user_rights_implementation(self, node: ast.FunctionDef):
        """Check if user rights (access, deletion, etc.) are properly implemented"""
        required_rights = GDPR_REQUIREMENTS['user_rights']['required_functions']
        if any(right in node.name for right in required_rights):
            # Check if proper security measures are in place
            if not self.has_authentication(node):
                self.gdpr.add_violation(
                    'unprotected_user_rights',
                    f'User rights function {node.name} lacks proper authentication',
                    node.lineno,
                    'high'
                )

    def has_authentication(self, node: ast.AST) -> bool:
        """Check if proper authentication is implemented"""
        auth_patterns = {
            'authenticate', 'login_required', 'auth', 'jwt', 
            'token', 'session', 'permission'
        }
        
        # Check decorators
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name):
                    if decorator.id in auth_patterns:
                        return True
                elif isinstance(decorator, ast.Call):
                    if isinstance(decorator.func, ast.Name):
                        if decorator.func.id in auth_patterns:
                            return True
        return False


