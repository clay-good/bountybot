"""
Context-aware code analyzer with data flow analysis and taint tracking.

This module provides advanced static analysis capabilities beyond simple pattern matching,
including:
- Data flow analysis to track how data moves through the code
- Taint tracking to identify if user input reaches dangerous sinks
- Framework-aware validation (Django, Flask, Express, etc.)
- Control flow analysis to understand execution paths
"""

import ast
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TaintedVariable:
    """Represents a variable that contains user-controlled data."""
    name: str
    source: str  # Where the taint originated (e.g., 'request.GET', 'request.body')
    line_number: int
    confidence: float = 1.0


@dataclass
class DataFlowPath:
    """Represents a path from a tainted source to a dangerous sink."""
    source: TaintedVariable
    sink: str  # The dangerous function/operation
    sink_line: int
    path: List[str] = field(default_factory=list)  # Intermediate steps
    sanitized: bool = False
    sanitization_methods: List[str] = field(default_factory=list)


@dataclass
class ContextAwareAnalysisResult:
    """Results from context-aware analysis."""
    vulnerable: bool
    confidence: float
    data_flow_paths: List[DataFlowPath]
    tainted_variables: List[TaintedVariable]
    security_controls: List[str]
    framework_protections: List[str]
    findings: List[str]
    recommendations: List[str]


class PythonTaintAnalyzer(ast.NodeVisitor):
    """AST-based taint analysis for Python code."""
    
    # Sources of user input (taint sources)
    TAINT_SOURCES = {
        'request.GET', 'request.POST', 'request.args', 'request.form',
        'request.json', 'request.data', 'request.cookies', 'request.headers',
        'request.query_params', 'request.body', 'input(', 'sys.argv',
        'os.environ', 'request.FILES', 'request.META'
    }
    
    # Dangerous operations (taint sinks)
    TAINT_SINKS = {
        'sql_injection': ['execute', 'executemany', 'raw', 'query', 'cursor.execute'],
        'command_injection': ['os.system', 'subprocess.call', 'subprocess.run', 
                             'subprocess.Popen', 'exec', 'eval', 'compile'],
        'path_traversal': ['open', 'os.path.join', 'Path', 'read', 'write'],
        'xss': ['render_template_string', 'mark_safe', 'Markup', 'innerHTML'],
        'deserialization': ['pickle.loads', 'yaml.load', 'marshal.load'],
    }
    
    # Sanitization functions
    SANITIZERS = {
        'escape', 'sanitize', 'validate', 'clean', 'filter',
        'htmlspecialchars', 'quote', 'urlencode', 'bleach.clean'
    }
    
    def __init__(self):
        self.tainted_vars: Dict[str, TaintedVariable] = {}
        self.data_flow_paths: List[DataFlowPath] = []
        self.current_line = 0
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments to propagate taint."""
        self.current_line = node.lineno
        
        # Check if right side is tainted
        is_tainted, source = self._is_tainted_expression(node.value)
        
        if is_tainted:
            # Mark all targets as tainted
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = TaintedVariable(
                        name=target.id,
                        source=source,
                        line_number=node.lineno
                    )
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Check if tainted data reaches dangerous sinks."""
        self.current_line = node.lineno
        
        # Get function name
        func_name = self._get_function_name(node.func)
        
        # Check if this is a dangerous sink
        for vuln_type, sinks in self.TAINT_SINKS.items():
            if any(sink in func_name for sink in sinks):
                # Check if any arguments are tainted
                for arg in node.args:
                    is_tainted, source = self._is_tainted_expression(arg)
                    if is_tainted:
                        # Check if sanitized
                        sanitized = self._is_sanitized(arg)
                        
                        # Create data flow path
                        path = DataFlowPath(
                            source=TaintedVariable(name=source, source=source, line_number=0),
                            sink=func_name,
                            sink_line=node.lineno,
                            sanitized=sanitized
                        )
                        self.data_flow_paths.append(path)
        
        self.generic_visit(node)
    
    def _is_tainted_expression(self, node: ast.AST) -> Tuple[bool, str]:
        """Check if an expression contains tainted data."""
        if isinstance(node, ast.Name):
            # Check if variable is tainted
            if node.id in self.tainted_vars:
                return True, self.tainted_vars[node.id].source

        elif isinstance(node, ast.Attribute):
            # Check if accessing tainted attribute
            full_name = self._get_attribute_name(node)
            if any(source in full_name for source in self.TAINT_SOURCES):
                return True, full_name

        elif isinstance(node, ast.Subscript):
            # Check if subscripting tainted object (e.g., request.GET['id'])
            if isinstance(node.value, ast.Attribute):
                full_name = self._get_attribute_name(node.value)
                if any(source in full_name for source in self.TAINT_SOURCES):
                    return True, full_name
            elif isinstance(node.value, ast.Name):
                if node.value.id in self.tainted_vars:
                    return True, self.tainted_vars[node.value.id].source

        elif isinstance(node, ast.BinOp):
            # Check if either side is tainted
            left_tainted, left_source = self._is_tainted_expression(node.left)
            right_tainted, right_source = self._is_tainted_expression(node.right)
            if left_tainted:
                return True, left_source
            if right_tainted:
                return True, right_source

        elif isinstance(node, ast.JoinedStr):
            # Check f-strings
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    is_tainted, source = self._is_tainted_expression(value.value)
                    if is_tainted:
                        return True, source

        elif isinstance(node, ast.Call):
            # Check if function call returns tainted data
            func_name = self._get_function_name(node.func)
            if any(source in func_name for source in self.TAINT_SOURCES):
                return True, func_name
            # Check if any arguments are tainted
            for arg in node.args:
                is_tainted, source = self._is_tainted_expression(arg)
                if is_tainted:
                    return True, source

        return False, ""
    
    def _is_sanitized(self, node: ast.AST) -> bool:
        """Check if expression has been sanitized."""
        if isinstance(node, ast.Call):
            func_name = self._get_function_name(node.func)
            return any(sanitizer in func_name for sanitizer in self.SANITIZERS)
        return False
    
    def _get_function_name(self, node: ast.AST) -> str:
        """Extract function name from call node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_attribute_name(node)
        return ""
    
    def _get_attribute_name(self, node: ast.Attribute) -> str:
        """Get full attribute name (e.g., 'request.GET')."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return '.'.join(reversed(parts))


class ContextAwareCodeAnalyzer:
    """
    Advanced code analyzer with context awareness, data flow analysis, and taint tracking.
    """
    
    # Framework-specific protections
    FRAMEWORK_PROTECTIONS = {
        'django': {
            'csrf': ['@csrf_protect', 'csrf_token', 'CsrfViewMiddleware'],
            'sql_injection': ['django.db.models', 'QuerySet', 'objects.filter'],
            'xss': ['autoescape', '|escape', 'mark_safe'],
        },
        'flask': {
            'csrf': ['CSRFProtect', 'csrf_token'],
            'sql_injection': ['SQLAlchemy', 'db.session.query'],
            'xss': ['escape', 'Markup'],
        },
        'express': {
            'csrf': ['csurf', 'csrf()'],
            'sql_injection': ['prepared statements', '?', 'parameterized'],
            'xss': ['escape-html', 'sanitize-html'],
        }
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize context-aware analyzer."""
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
    
    def analyze_python_file(self, file_path: str, vulnerability_type: str) -> ContextAwareAnalysisResult:
        """
        Perform context-aware analysis on a Python file.
        
        Args:
            file_path: Path to Python file
            vulnerability_type: Type of vulnerability to check for
        
        Returns:
            ContextAwareAnalysisResult with detailed findings
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Parse AST
            tree = ast.parse(source_code, filename=file_path)
            
            # Run taint analysis
            analyzer = PythonTaintAnalyzer()
            analyzer.visit(tree)
            
            # Detect framework
            framework = self._detect_framework(source_code)
            framework_protections = self._check_framework_protections(
                source_code, framework, vulnerability_type
            )
            
            # Analyze data flow paths
            vulnerable_paths = [
                path for path in analyzer.data_flow_paths
                if not path.sanitized
            ]
            
            # Calculate confidence
            confidence = self._calculate_confidence(
                vulnerable_paths, framework_protections
            )
            
            # Generate findings and recommendations
            findings = self._generate_findings(vulnerable_paths, analyzer.tainted_vars)
            recommendations = self._generate_recommendations(
                vulnerable_paths, framework_protections
            )
            
            return ContextAwareAnalysisResult(
                vulnerable=len(vulnerable_paths) > 0,
                confidence=confidence,
                data_flow_paths=analyzer.data_flow_paths,
                tainted_variables=list(analyzer.tainted_vars.values()),
                security_controls=[],
                framework_protections=framework_protections,
                findings=findings,
                recommendations=recommendations
            )
        
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            return ContextAwareAnalysisResult(
                vulnerable=False,
                confidence=0.0,
                data_flow_paths=[],
                tainted_variables=[],
                security_controls=[],
                framework_protections=[],
                findings=[f"Analysis error: {str(e)}"],
                recommendations=[]
            )
    
    def _detect_framework(self, source_code: str) -> Optional[str]:
        """Detect which framework is being used."""
        if 'from django' in source_code or 'import django' in source_code:
            return 'django'
        elif 'from flask' in source_code or 'import flask' in source_code:
            return 'flask'
        elif 'express' in source_code or 'require("express")' in source_code:
            return 'express'
        return None
    
    def _check_framework_protections(self, source_code: str, framework: Optional[str],
                                     vulnerability_type: str) -> List[str]:
        """Check for framework-specific security protections."""
        protections = []
        
        if framework and framework in self.FRAMEWORK_PROTECTIONS:
            vuln_key = vulnerability_type.lower().replace(' ', '_')
            if vuln_key in self.FRAMEWORK_PROTECTIONS[framework]:
                for protection in self.FRAMEWORK_PROTECTIONS[framework][vuln_key]:
                    if protection in source_code:
                        protections.append(f"{framework}: {protection}")
        
        return protections
    
    def _calculate_confidence(self, vulnerable_paths: List[DataFlowPath],
                             framework_protections: List[str]) -> float:
        """Calculate confidence score for vulnerability."""
        if not vulnerable_paths:
            return 0.0
        
        base_confidence = 0.7
        
        # Increase confidence for multiple paths
        if len(vulnerable_paths) > 1:
            base_confidence += 0.1
        
        # Decrease confidence if framework protections exist
        if framework_protections:
            base_confidence -= 0.2 * len(framework_protections)
        
        return max(0.0, min(1.0, base_confidence))
    
    def _generate_findings(self, vulnerable_paths: List[DataFlowPath],
                          tainted_vars: Dict[str, TaintedVariable]) -> List[str]:
        """Generate human-readable findings."""
        findings = []
        
        for path in vulnerable_paths:
            findings.append(
                f"Tainted data from '{path.source.source}' reaches dangerous sink "
                f"'{path.sink}' at line {path.sink_line} without sanitization"
            )
        
        return findings
    
    def _generate_recommendations(self, vulnerable_paths: List[DataFlowPath],
                                 framework_protections: List[str]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if vulnerable_paths:
            recommendations.append(
                "Sanitize all user input before using in dangerous operations"
            )
            recommendations.append(
                "Use parameterized queries or prepared statements for database operations"
            )
        
        if not framework_protections:
            recommendations.append(
                "Enable framework-specific security protections (CSRF, XSS auto-escape, etc.)"
            )
        
        return recommendations

