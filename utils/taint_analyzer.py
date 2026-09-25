"""
Taint Analysis Module for BlueSpunge

This module implements data flow analysis to track how untrusted data moves through
applications, identifying potential injection points that static pattern matching might miss.
"""

import os
import ast
import re
import logging
import networkx as nx
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define source and sink categories
SOURCES = {
    'user_input': [
        'request.form', 'request.args', 'request.json', 'request.data',
        'input(', 'sys.argv', 'os.environ', 'flask.request',
        'get_json()', 'parse_args()'
    ],
    'file_input': [
        'open(', 'read(', 'readline(', 'readlines(',
        'load(', 'loads(', 'parse('
    ],
    'network_input': [
        'recv(', 'recvfrom(', 'recvmsg(',
        'urlopen(', 'get(', 'post(',
        'requests.', 'urllib'
    ],
    'database_input': [
        'execute(', 'fetchone(', 'fetchall(', 'fetchmany(',
        'cursor.', 'connection.'
    ]
}

SINKS = {
    'sql_injection': [
        'execute(', 'executemany(', 'cursor.execute',
        'raw_connection', 'raw_cursor'
    ],
    'command_injection': [
        'os.system(', 'subprocess.', 'popen(', 'exec(',
        'eval(', 'execfile(', 'os.popen('
    ],
    'xss': [
        'render_template(', 'render(', 'jsonify(',
        'make_response(', 'Response(', 'send_file('
    ],
    'path_traversal': [
        'open(', 'os.path', 'os.makedirs', 'os.mkdir',
        'os.rename', 'os.remove', 'os.unlink'
    ],
    'deserialization': [
        'pickle.loads', 'yaml.load', 'marshal.loads',
        'json.loads', 'unserialize('
    ]
}

SANITIZERS = {
    'sql_injection': [
        'parameterize', 'prepare', 'quote_plus', 'escape_string',
        'sanitize_sql', 'bindparam'
    ],
    'command_injection': [
        'shlex.quote', 'pipes.quote', 'escapeshellarg',
        'escapeshellcmd', 'sanitize_command'
    ],
    'xss': [
        'escape', 'sanitize', 'html.escape', 'cgi.escape',
        'bleach.clean', 'markupsafe'
    ],
    'path_traversal': [
        'os.path.abspath', 'os.path.normpath', 'realpath',
        'canonicalize', 'sanitize_filename'
    ],
    'deserialization': [
        'safe_load', 'json.loads', 'hmac.verify', 'validate_schema'
    ]
}

class TaintNode:
    """Represents a node in the taint analysis graph"""
    def __init__(self, name: str, line_no: int, file_path: str, node_type: str = 'variable'):
        self.name = name
        self.line_no = line_no
        self.file_path = file_path
        self.node_type = node_type  # variable, source, sink, sanitizer
        self.tainted = False
        self.source_type = None
        self.sink_type = None
        self.sanitizer_type = None
    
    def __str__(self):
        return f"{self.name} ({self.node_type}) at {self.file_path}:{self.line_no}"

class TaintPath:
    """Represents a path from a source to a sink"""
    def __init__(self, source: TaintNode, sink: TaintNode, path: List[TaintNode]):
        self.source = source
        self.sink = sink
        self.path = path
        self.sanitized = False
        self.risk_level = self._calculate_risk()
    
    def _calculate_risk(self) -> str:
        """Calculate risk level based on path characteristics"""
        if self.sanitized:
            return "Low"
        
        # Higher risk for certain combinations
        high_risk_combos = [
            ('user_input', 'sql_injection'),
            ('user_input', 'command_injection'),
            ('network_input', 'command_injection'),
            ('user_input', 'xss')
        ]
        
        if (self.source.source_type, self.sink.sink_type) in high_risk_combos:
            return "High"
        
        return "Medium"
    
    def __str__(self):
        return (f"Taint path: {self.source.name} -> {self.sink.name} "
                f"({self.risk_level} risk, {'sanitized' if self.sanitized else 'not sanitized'})")

class TaintAnalyzer:
    """Main class for performing taint analysis"""
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.graph = nx.DiGraph()
        self.sources: List[TaintNode] = []
        self.sinks: List[TaintNode] = []
        self.sanitizers: List[TaintNode] = []
        self.taint_paths: List[TaintPath] = []
        self.file_parsers = {
            '.py': self._parse_python_file,
            '.js': self._parse_javascript_file,
            '.php': self._parse_php_file,
            '.java': self._parse_java_file
        }
    
    def analyze_repository(self) -> Dict[str, Any]:
        """Analyze the entire repository for taint flows"""
        logger.info(f"Starting taint analysis for repository: {self.repo_path}")
        
        # Walk through repository and analyze each file
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.repo_path)
                
                # Skip certain directories and files
                if any(part.startswith('.') or part in ['node_modules', 'venv', '__pycache__'] 
                       for part in rel_path.split(os.sep)):
                    continue
                
                # Get file extension
                _, ext = os.path.splitext(file)
                
                # If we have a parser for this file type, analyze it
                if ext in self.file_parsers:
                    try:
                        logger.debug(f"Analyzing file: {rel_path}")
                        self.file_parsers[ext](file_path, rel_path)
                    except Exception as e:
                        logger.error(f"Error analyzing {rel_path}: {str(e)}")
        
        # Find taint paths
        self._find_taint_paths()
        
        # Generate report
        return self._generate_report()
    
    def _parse_python_file(self, file_path: str, rel_path: str) -> None:
        """Parse a Python file for taint analysis"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse the AST
            tree = ast.parse(content, filename=file_path)
            
            # Simple visitor to find sources, sinks, and variables
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check if this is a function call that could be a source or sink
                    func_name = self._get_call_name(node)
                    line_no = getattr(node, 'lineno', 0)
                    
                    # Check if it's a source
                    for source_type, patterns in SOURCES.items():
                        if any(pattern in func_name for pattern in patterns):
                            source_node = TaintNode(func_name, line_no, rel_path, 'source')
                            source_node.source_type = source_type
                            source_node.tainted = True
                            self.sources.append(source_node)
                            self.graph.add_node(source_node)
                            break
                    
                    # Check if it's a sink
                    for sink_type, patterns in SINKS.items():
                        if any(pattern in func_name for pattern in patterns):
                            sink_node = TaintNode(func_name, line_no, rel_path, 'sink')
                            sink_node.sink_type = sink_type
                            self.sinks.append(sink_node)
                            self.graph.add_node(sink_node)
                            break
                    
                    # Check if it's a sanitizer
                    for sanitizer_type, patterns in SANITIZERS.items():
                        if any(pattern in func_name for pattern in patterns):
                            sanitizer_node = TaintNode(func_name, line_no, rel_path, 'sanitizer')
                            sanitizer_node.sanitizer_type = sanitizer_type
                            self.sanitizers.append(sanitizer_node)
                            self.graph.add_node(sanitizer_node)
                            break
                
                # Track variable assignments
                elif isinstance(node, ast.Assign):
                    line_no = getattr(node, 'lineno', 0)
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_node = TaintNode(target.id, line_no, rel_path, 'variable')
                            self.graph.add_node(var_node)
                            
                            # If the value is a call that's a source, add an edge
                            if isinstance(node.value, ast.Call):
                                func_name = self._get_call_name(node.value)
                                for source in self.sources:
                                    if source.name == func_name and source.line_no == line_no:
                                        self.graph.add_edge(source, var_node)
                                        var_node.tainted = True
                                        break
        
        except Exception as e:
            logger.error(f"Error parsing Python file {file_path}: {str(e)}")
    
    def _parse_javascript_file(self, file_path: str, rel_path: str) -> None:
        """Parse a JavaScript file for taint analysis (simplified)"""
        # In a real implementation, we would use a JavaScript parser like esprima
        # For now, we'll use a simplified regex-based approach
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Find potential sources
            for source_type, patterns in SOURCES.items():
                for pattern in patterns:
                    for match in re.finditer(r'\b' + re.escape(pattern), content):
                        line_no = content[:match.start()].count('\n') + 1
                        source_node = TaintNode(pattern, line_no, rel_path, 'source')
                        source_node.source_type = source_type
                        source_node.tainted = True
                        self.sources.append(source_node)
                        self.graph.add_node(source_node)
            
            # Find potential sinks
            for sink_type, patterns in SINKS.items():
                for pattern in patterns:
                    for match in re.finditer(r'\b' + re.escape(pattern), content):
                        line_no = content[:match.start()].count('\n') + 1
                        sink_node = TaintNode(pattern, line_no, rel_path, 'sink')
                        sink_node.sink_type = sink_type
                        self.sinks.append(sink_node)
                        self.graph.add_node(sink_node)
            
            # Find potential sanitizers
            for sanitizer_type, patterns in SANITIZERS.items():
                for pattern in patterns:
                    for match in re.finditer(r'\b' + re.escape(pattern), content):
                        line_no = content[:match.start()].count('\n') + 1
                        sanitizer_node = TaintNode(pattern, line_no, rel_path, 'sanitizer')
                        sanitizer_node.sanitizer_type = sanitizer_type
                        self.sanitizers.append(sanitizer_node)
                        self.graph.add_node(sanitizer_node)
        
        except Exception as e:
            logger.error(f"Error parsing JavaScript file {file_path}: {str(e)}")
    
    def _parse_php_file(self, file_path: str, rel_path: str) -> None:
        """Parse a PHP file for taint analysis (placeholder)"""
        # Similar to JavaScript, we'd use a proper PHP parser in a real implementation
        logger.info(f"PHP parsing not fully implemented for {rel_path}")
    
    def _parse_java_file(self, file_path: str, rel_path: str) -> None:
        """Parse a Java file for taint analysis (placeholder)"""
        # We'd use a Java parser like JavaParser in a real implementation
        logger.info(f"Java parsing not fully implemented for {rel_path}")
    
    def _get_call_name(self, node: ast.Call) -> str:
        """Extract the full name of a function call"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handle attribute access like module.function()
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return "unknown"
    
    def _find_taint_paths(self) -> None:
        """Find paths from sources to sinks in the taint graph"""
        logger.info("Finding taint paths in the graph")
        
        # For each source and sink, try to find a path
        for source in self.sources:
            for sink in self.sinks:
                try:
                    # Check if there's a path from source to sink
                    if nx.has_path(self.graph, source, sink):
                        path = nx.shortest_path(self.graph, source, sink)
                        
                        # Check if the path goes through a sanitizer
                        sanitized = False
                        for node in path:
                            if node in self.sanitizers:
                                # Check if sanitizer type matches sink type
                                if node.sanitizer_type == sink.sink_type:
                                    sanitized = True
                                    break
                        
                        # Create a taint path
                        taint_path = TaintPath(source, sink, path)
                        taint_path.sanitized = sanitized
                        self.taint_paths.append(taint_path)
                except nx.NetworkXNoPath:
                    # No path exists
                    continue
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate a report of the taint analysis results"""
        logger.info("Generating taint analysis report")
        
        # Group paths by risk level
        paths_by_risk = {
            'High': [],
            'Medium': [],
            'Low': []
        }
        
        for path in self.taint_paths:
            paths_by_risk[path.risk_level].append({
                'source': {
                    'name': path.source.name,
                    'type': path.source.source_type,
                    'file': path.source.file_path,
                    'line': path.source.line_no
                },
                'sink': {
                    'name': path.sink.name,
                    'type': path.sink.sink_type,
                    'file': path.sink.file_path,
                    'line': path.sink.line_no
                },
                'sanitized': path.sanitized,
                'path_length': len(path.path),
                'risk_level': path.risk_level
            })
        
        # Summary statistics
        total_sources = len(self.sources)
        total_sinks = len(self.sinks)
        total_sanitizers = len(self.sanitizers)
        total_paths = len(self.taint_paths)
        
        high_risk_paths = len(paths_by_risk['High'])
        medium_risk_paths = len(paths_by_risk['Medium'])
        low_risk_paths = len(paths_by_risk['Low'])
        
        return {
            'summary': {
                'total_sources': total_sources,
                'total_sinks': total_sinks,
                'total_sanitizers': total_sanitizers,
                'total_paths': total_paths,
                'high_risk_paths': high_risk_paths,
                'medium_risk_paths': medium_risk_paths,
                'low_risk_paths': low_risk_paths
            },
            'paths': paths_by_risk
        }

def run_taint_analysis(repo_path: str) -> Dict[str, Any]:
    """Run taint analysis on a repository"""
    analyzer = TaintAnalyzer(repo_path)
    return analyzer.analyze_repository()
