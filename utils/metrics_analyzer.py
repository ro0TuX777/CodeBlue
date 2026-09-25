import os
import re
import logging
import subprocess
from datetime import datetime, timezone
import git
import numpy as np

def extract_metrics_from_scan(repo_name, scan_result, repo_path):
    """
    Extract metrics from scan results for dashboard visualization
    
    Args:
        repo_name (str): Name of the repository
        scan_result (dict): Results from the security scan
        repo_path (str): Path to the repository
        
    Returns:
        dict: Extracted metrics
    """
    metrics = {
        'repo_name': repo_name,
        'scan_date': datetime.now(timezone.utc),
        'high_severity_issues': 0,
        'medium_severity_issues': 0,
        'low_severity_issues': 0,
        'total_issues': 0,
        'code_complexity': 0.0,
        'code_duplication': 0.0,
        'maintainability_index': 0.0,
        'dependencies_with_vulnerabilities': 0,
        'lines_of_code': 0,
        'test_coverage': 0.0
    }
    
    # Extract security metrics from scan result
    if 'output' in scan_result:
        output = scan_result['output']
        
        # Count severity levels from Bandit output
        high_match = re.search(r'High: (\d+)', output)
        if high_match:
            metrics['high_severity_issues'] = int(high_match.group(1))
            
        medium_match = re.search(r'Medium: (\d+)', output)
        if medium_match:
            metrics['medium_severity_issues'] = int(medium_match.group(1))
            
        low_match = re.search(r'Low: (\d+)', output)
        if low_match:
            metrics['low_severity_issues'] = int(low_match.group(1))
        
        # Extract dependency vulnerabilities from Safety output
        vuln_match = re.search(r'Found (\d+) vulnerability', output)
        if vuln_match:
            metrics['dependencies_with_vulnerabilities'] = int(vuln_match.group(1))
        
        # Calculate total issues
        metrics['total_issues'] = (
            metrics['high_severity_issues'] + 
            metrics['medium_severity_issues'] + 
            metrics['low_severity_issues']
        )
    
    # Extract code complexity metrics if radon was run
    try:
        radon_output = run_radon_cc(repo_path)
        metrics['code_complexity'] = extract_average_complexity(radon_output)
        
        # Get maintainability index
        mi_output = run_radon_mi(repo_path)
        metrics['maintainability_index'] = extract_maintainability_index(mi_output)
    except Exception as e:
        logging.error(f"Error extracting complexity metrics: {str(e)}")
    
    # Count lines of code
    try:
        metrics['lines_of_code'] = count_lines_of_code(repo_path)
    except Exception as e:
        logging.error(f"Error counting lines of code: {str(e)}")
    
    # Estimate code duplication (simplified approach)
    try:
        metrics['code_duplication'] = estimate_code_duplication(repo_path)
    except Exception as e:
        logging.error(f"Error estimating code duplication: {str(e)}")
    
    return metrics

def run_radon_cc(repo_path):
    """Run radon to get cyclomatic complexity metrics"""
    try:
        result = subprocess.run(
            ['radon', 'cc', '--average', '--total-average', repo_path], 
            capture_output=True, 
            text=True
        )
        return result.stdout
    except Exception as e:
        logging.error(f"Error running radon cc: {str(e)}")
        return ""

def run_radon_mi(repo_path):
    """Run radon to get maintainability index"""
    try:
        result = subprocess.run(
            ['radon', 'mi', '--min', repo_path], 
            capture_output=True, 
            text=True
        )
        return result.stdout
    except Exception as e:
        logging.error(f"Error running radon mi: {str(e)}")
        return ""

def extract_average_complexity(radon_output):
    """Extract average complexity from radon output"""
    match = re.search(r'Average complexity: ([\d\.]+)', radon_output)
    if match:
        return float(match.group(1))
    return 0.0

def extract_maintainability_index(mi_output):
    """Extract maintainability index from radon output"""
    # Calculate average MI from all files
    mi_values = re.findall(r'- \w+\.py \((\d+\.\d+)\)', mi_output)
    if mi_values:
        return sum(float(val) for val in mi_values) / len(mi_values)
    return 0.0

def count_lines_of_code(repo_path):
    """Count total lines of code in the repository"""
    total_lines = 0
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.py', '.js', '.java', '.c', '.cpp', '.h', '.hpp', '.cs')):
                try:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        total_lines += sum(1 for _ in f)
                except Exception as e:
                    logging.error(f"Error counting lines in {file_path}: {str(e)}")
    return total_lines

def estimate_code_duplication(repo_path):
    """Estimate code duplication percentage (simplified approach)"""
    # This is a simplified approach - in a real implementation, you would use a tool like PMD CPD
    # For now, we'll return a random value between 0-20% for demonstration
    return np.random.uniform(0, 20.0)

def calculate_file_risks(repo_name, repo_path):
    """
    Calculate risk scores for each file in the repository
    
    Args:
        repo_name (str): Name of the repository
        repo_path (str): Path to the repository
        
    Returns:
        list: List of file risk dictionaries
    """
    file_risks = []
    
    # Get all relevant files
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.py', '.js', '.java', '.c', '.cpp', '.h', '.hpp', '.cs')):
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                # Skip files in .git, venv, node_modules, etc.
                if any(part.startswith('.') or part in ['venv', 'node_modules', '__pycache__'] 
                       for part in relative_path.split(os.sep)):
                    continue
                
                try:
                    # Calculate risk metrics for this file
                    risk_data = {
                        'repo_name': repo_name,
                        'file_path': relative_path,
                        'scan_date': datetime.now(timezone.utc)
                    }
                    
                    # Calculate complexity risk
                    complexity_data = calculate_file_complexity(file_path)
                    risk_data.update(complexity_data)
                    
                    # Calculate churn risk
                    churn_data = calculate_file_churn(repo_path, relative_path)
                    risk_data.update(churn_data)
                    
                    # Calculate security risk (placeholder - would use actual security scan results)
                    security_data = estimate_security_risk(file_path)
                    risk_data.update(security_data)
                    
                    # Calculate total risk score (weighted average)
                    risk_data['total_risk'] = (
                        risk_data['security_risk'] * 0.5 +
                        risk_data['complexity_risk'] * 0.3 +
                        risk_data['churn_risk'] * 0.2
                    )
                    
                    file_risks.append(risk_data)
                except Exception as e:
                    logging.error(f"Error calculating risk for {file_path}: {str(e)}")
    
    return file_risks

def calculate_file_complexity(file_path):
    """Calculate complexity metrics for a file"""
    try:
        # Run radon on the specific file
        result = subprocess.run(
            ['radon', 'cc', file_path], 
            capture_output=True, 
            text=True
        )
        
        # Parse complexity values
        complexity_values = re.findall(r'[A-Z] \(\d+\)', result.stdout)
        
        # Count by complexity class
        complexity_counts = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'E': 0, 'F': 0}
        for value in complexity_values:
            complexity_class = value[0]
            if complexity_class in complexity_counts:
                complexity_counts[complexity_class] += 1
        
        # Calculate weighted complexity score (0-100)
        weights = {'A': 0, 'B': 20, 'C': 40, 'D': 60, 'E': 80, 'F': 100}
        total_functions = sum(complexity_counts.values()) or 1  # Avoid division by zero
        
        weighted_score = sum(
            complexity_counts[cls] * weights[cls] for cls in complexity_counts
        ) / total_functions
        
        # Get cyclomatic complexity
        cc_match = re.search(r'avg: ([0-9.]+)', result.stdout)
        cyclomatic_complexity = float(cc_match.group(1)) if cc_match else 1.0
        
        # Estimate cognitive complexity (simplified)
        cognitive_complexity = cyclomatic_complexity * 1.2
        
        return {
            'complexity_risk': min(100, weighted_score),
            'cyclomatic_complexity': cyclomatic_complexity,
            'cognitive_complexity': cognitive_complexity
        }
    except Exception as e:
        logging.error(f"Error calculating complexity for {file_path}: {str(e)}")
        return {
            'complexity_risk': 0.0,
            'cyclomatic_complexity': 0.0,
            'cognitive_complexity': 0.0
        }

def calculate_file_churn(repo_path, relative_file_path):
    """Calculate churn (change frequency) for a file"""
    try:
        # Initialize Git repository
        repo = git.Repo(repo_path)
        file_path = os.path.join(repo_path, relative_file_path)
        
        # Get commit history for the file
        commits = list(repo.iter_commits(paths=file_path, max_count=50))
        
        if not commits:
            return {
                'churn_risk': 0.0,
                'lines_changed_last_month': 0
            }
        
        # Count lines changed in the last month
        one_month_ago = datetime.now(timezone.utc).timestamp() - (30 * 24 * 60 * 60)
        recent_commits = [c for c in commits if c.committed_date > one_month_ago]
        
        lines_changed = 0
        for commit in recent_commits:
            # Get the diff for this file in this commit
            diffs = commit.diff(commit.parents[0] if commit.parents else git.NULL_TREE)
            for diff in diffs:
                if diff.a_path == relative_file_path or diff.b_path == relative_file_path:
                    # Count added and deleted lines
                    lines_changed += diff.stats.get('insertions', 0)
                    lines_changed += diff.stats.get('deletions', 0)
        
        # Calculate churn risk (0-100 scale)
        churn_risk = min(100, lines_changed / 2)
        
        return {
            'churn_risk': churn_risk,
            'lines_changed_last_month': lines_changed
        }
    except Exception as e:
        logging.error(f"Error calculating churn for {relative_file_path}: {str(e)}")
        return {
            'churn_risk': 0.0,
            'lines_changed_last_month': 0
        }

def estimate_security_risk(file_path):
    """Estimate security risk for a file (placeholder)"""
    # In a real implementation, this would use actual security scan results
    # For now, we'll use a simple heuristic based on file extension and content
    
    try:
        # Higher risk for certain file types
        ext = os.path.splitext(file_path)[1].lower()
        base_risk = {
            '.py': 30,
            '.js': 40,
            '.php': 50,
            '.java': 30,
            '.c': 60,
            '.cpp': 60
        }.get(ext, 20)
        
        # Check file content for potential security issues
        issue_count = 0
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Look for potential security keywords
            security_patterns = [
                r'password', r'secret', r'token', r'auth', r'api_key',
                r'eval\(', r'exec\(', r'subprocess', r'shell=True',
                r'sql.*SELECT', r'\.execute\(', r'\.query\('
            ]
            
            for pattern in security_patterns:
                issue_count += len(re.findall(pattern, content, re.IGNORECASE))
        
        # Calculate final risk score (0-100)
        security_risk = min(100, base_risk + (issue_count * 5))
        
        return {
            'security_risk': security_risk,
            'issue_count': issue_count
        }
    except Exception as e:
        logging.error(f"Error estimating security risk for {file_path}: {str(e)}")
        return {
            'security_risk': 0.0,
            'issue_count': 0
        }
