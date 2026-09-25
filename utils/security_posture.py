"""
Security Posture Scoring System for BlueSpunge

This module implements a comprehensive scoring system that quantifies the overall
security posture of a repository based on multiple factors.
"""

import os
import logging
import math
import re
from datetime import datetime, timezone
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define scoring weights for different categories
SCORING_WEIGHTS = {
    'vulnerability': {
        'weight': 0.35,
        'components': {
            'high_severity': 10.0,
            'medium_severity': 5.0,
            'low_severity': 2.0,
            'info_severity': 0.5
        }
    },
    'code_quality': {
        'weight': 0.25,
        'components': {
            'complexity': 0.4,
            'duplication': 0.3,
            'maintainability': 0.3
        }
    },
    'security_practices': {
        'weight': 0.20,
        'components': {
            'input_validation': 0.25,
            'output_encoding': 0.25,
            'authentication': 0.25,
            'access_control': 0.25
        }
    },
    'testing': {
        'weight': 0.10,
        'components': {
            'test_coverage': 0.6,
            'security_tests': 0.4
        }
    },
    'dependencies': {
        'weight': 0.10,
        'components': {
            'vulnerable_deps': 0.7,
            'outdated_deps': 0.3
        }
    }
}

# Define grade thresholds
GRADE_THRESHOLDS = {
    'A+': 95,
    'A': 90,
    'A-': 85,
    'B+': 80,
    'B': 75,
    'B-': 70,
    'C+': 65,
    'C': 60,
    'C-': 55,
    'D+': 50,
    'D': 45,
    'D-': 40,
    'F': 0
}

class SecurityPostureScorer:
    """Main class for calculating security posture scores"""
    def __init__(self, repo_path: str, repo_name: str):
        self.repo_path = repo_path
        self.repo_name = repo_name
        self.scores = {}
        self.grade = 'F'
        self.timestamp = datetime.now(timezone.utc)

    def calculate_score(self, scan_results: Dict[str, Any], metrics: Dict[str, Any],
                        taint_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate the overall security posture score"""
        logger.info(f"Calculating security posture score for {self.repo_name}")

        # Calculate scores for each category
        vulnerability_score = self._calculate_vulnerability_score(scan_results)
        code_quality_score = self._calculate_code_quality_score(metrics)
        security_practices_score = self._calculate_security_practices_score(scan_results, taint_results)
        testing_score = self._calculate_testing_score(metrics)
        dependencies_score = self._calculate_dependencies_score(scan_results)

        # Store individual category scores
        self.scores = {
            'vulnerability': vulnerability_score,
            'code_quality': code_quality_score,
            'security_practices': security_practices_score,
            'testing': testing_score,
            'dependencies': dependencies_score
        }

        # Calculate weighted overall score
        overall_score = (
            vulnerability_score * SCORING_WEIGHTS['vulnerability']['weight'] +
            code_quality_score * SCORING_WEIGHTS['code_quality']['weight'] +
            security_practices_score * SCORING_WEIGHTS['security_practices']['weight'] +
            testing_score * SCORING_WEIGHTS['testing']['weight'] +
            dependencies_score * SCORING_WEIGHTS['dependencies']['weight']
        )

        # Determine grade
        self.grade = self._determine_grade(overall_score)

        # Generate recommendations
        recommendations = self._generate_recommendations()

        return {
            'repo_name': self.repo_name,
            'timestamp': self.timestamp,
            'overall_score': overall_score,
            'grade': self.grade,
            'category_scores': self.scores,
            'recommendations': recommendations
        }

    def _calculate_vulnerability_score(self, scan_results: Dict[str, Any]) -> float:
        """Calculate score based on vulnerabilities found"""
        try:
            # Extract vulnerability counts from scan results
            output = scan_results.get('output', '')

            # Count vulnerabilities by severity
            high_count = output.count('High:') or 0
            medium_count = output.count('Medium:') or 0
            low_count = output.count('Low:') or 0
            info_count = output.count('Info:') or 0

            # Calculate raw penalty score (higher is worse)
            raw_penalty = (
                high_count * SCORING_WEIGHTS['vulnerability']['components']['high_severity'] +
                medium_count * SCORING_WEIGHTS['vulnerability']['components']['medium_severity'] +
                low_count * SCORING_WEIGHTS['vulnerability']['components']['low_severity'] +
                info_count * SCORING_WEIGHTS['vulnerability']['components']['info_severity']
            )

            # Convert to a 0-100 score (higher is better)
            # Using an exponential decay function to penalize vulnerabilities
            score = 100 * math.exp(-0.05 * raw_penalty)

            return max(0, min(100, score))

        except Exception as e:
            logger.error(f"Error calculating vulnerability score: {str(e)}")
            return 50.0  # Default to middle score on error

    def _calculate_code_quality_score(self, metrics: Dict[str, Any]) -> float:
        """Calculate score based on code quality metrics"""
        try:
            # Extract metrics
            complexity = metrics.get('code_complexity', 10.0)  # Higher is worse
            duplication = metrics.get('code_duplication', 20.0)  # Percentage, higher is worse
            maintainability = metrics.get('maintainability_index', 50.0)  # Higher is better

            # Normalize complexity (0-100, higher is better)
            complexity_score = 100 * math.exp(-0.1 * complexity)

            # Normalize duplication (0-100, higher is better)
            duplication_score = 100 - duplication

            # Normalize maintainability (0-100, higher is better)
            maintainability_score = maintainability

            # Calculate weighted score
            score = (
                complexity_score * SCORING_WEIGHTS['code_quality']['components']['complexity'] +
                duplication_score * SCORING_WEIGHTS['code_quality']['components']['duplication'] +
                maintainability_score * SCORING_WEIGHTS['code_quality']['components']['maintainability']
            )

            return max(0, min(100, score))

        except Exception as e:
            logger.error(f"Error calculating code quality score: {str(e)}")
            return 50.0  # Default to middle score on error

    def _calculate_security_practices_score(self, scan_results: Dict[str, Any],
                                           taint_results: Dict[str, Any]) -> float:
        """Calculate score based on security practices"""
        try:
            # Extract taint analysis results
            taint_summary = taint_results.get('summary', {})
            total_paths = taint_summary.get('total_paths', 0)
            high_risk_paths = taint_summary.get('high_risk_paths', 0)

            # Calculate input validation score based on taint analysis
            if total_paths > 0:
                input_validation_score = 100 * (1 - (high_risk_paths / total_paths))
            else:
                input_validation_score = 80  # Default if no paths found

            # Extract other security practices from scan results
            output = scan_results.get('output', '')

            # Check for output encoding practices
            output_encoding_keywords = ['escape', 'sanitize', 'encode', 'htmlspecialchars']
            output_encoding_score = 50  # Base score
            for keyword in output_encoding_keywords:
                if keyword in output.lower():
                    output_encoding_score += 10
            output_encoding_score = min(100, output_encoding_score)

            # Check for authentication practices
            auth_keywords = ['authentication', 'password', 'login', 'session', 'token']
            auth_score = 50  # Base score
            for keyword in auth_keywords:
                if keyword in output.lower():
                    auth_score += 10
            auth_score = min(100, auth_score)

            # Check for access control practices
            access_keywords = ['authorization', 'permission', 'role', 'access control', 'rbac']
            access_score = 50  # Base score
            for keyword in access_keywords:
                if keyword in output.lower():
                    access_score += 10
            access_score = min(100, access_score)

            # Calculate weighted score
            score = (
                input_validation_score * SCORING_WEIGHTS['security_practices']['components']['input_validation'] +
                output_encoding_score * SCORING_WEIGHTS['security_practices']['components']['output_encoding'] +
                auth_score * SCORING_WEIGHTS['security_practices']['components']['authentication'] +
                access_score * SCORING_WEIGHTS['security_practices']['components']['access_control']
            )

            return max(0, min(100, score))

        except Exception as e:
            logger.error(f"Error calculating security practices score: {str(e)}")
            return 50.0  # Default to middle score on error

    def _calculate_testing_score(self, metrics: Dict[str, Any]) -> float:
        """Calculate score based on testing metrics"""
        try:
            # Extract metrics
            test_coverage = metrics.get('test_coverage', 0.0)  # Percentage, higher is better

            # Estimate security tests based on file patterns
            security_tests_score = 0
            test_dir = os.path.join(self.repo_path, 'tests')
            if os.path.exists(test_dir) and os.path.isdir(test_dir):
                security_test_keywords = ['security', 'vulnerability', 'injection', 'xss', 'csrf']
                for root, _, files in os.walk(test_dir):
                    for file in files:
                        if file.startswith('test_') or file.endswith('_test.py'):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read().lower()
                                    for keyword in security_test_keywords:
                                        if keyword in content:
                                            security_tests_score += 10
                                            break
                            except Exception as e:
                                logging.debug(f"Could not read test file {file_path}: {e}")

            security_tests_score = min(100, security_tests_score)

            # Calculate weighted score
            score = (
                test_coverage * SCORING_WEIGHTS['testing']['components']['test_coverage'] +
                security_tests_score * SCORING_WEIGHTS['testing']['components']['security_tests']
            )

            return max(0, min(100, score))

        except Exception as e:
            logger.error(f"Error calculating testing score: {str(e)}")
            return 50.0  # Default to middle score on error

    def _calculate_dependencies_score(self, scan_results: Dict[str, Any]) -> float:
        """Calculate score based on dependencies"""
        try:
            # Extract dependency information from scan results
            output = scan_results.get('output', '')

            # Count vulnerable dependencies
            vulnerable_deps_match = re.search(r'Found (\d+) vulnerable', output)
            vulnerable_deps = int(vulnerable_deps_match.group(1)) if vulnerable_deps_match else 0

            # Estimate total dependencies
            total_deps_match = re.search(r'Checked (\d+) packages', output)
            total_deps = int(total_deps_match.group(1)) if total_deps_match else 10

            # Calculate vulnerable dependencies score
            if total_deps > 0:
                vulnerable_deps_score = 100 * (1 - (vulnerable_deps / total_deps))
            else:
                vulnerable_deps_score = 80  # Default if no dependencies found

            # Estimate outdated dependencies score (simplified)
            outdated_deps_score = 70  # Default score

            # Calculate weighted score
            score = (
                vulnerable_deps_score * SCORING_WEIGHTS['dependencies']['components']['vulnerable_deps'] +
                outdated_deps_score * SCORING_WEIGHTS['dependencies']['components']['outdated_deps']
            )

            return max(0, min(100, score))

        except Exception as e:
            logger.error(f"Error calculating dependencies score: {str(e)}")
            return 50.0  # Default to middle score on error

    def _determine_grade(self, score: float) -> str:
        """Determine letter grade based on score"""
        for grade, threshold in sorted(GRADE_THRESHOLDS.items(), key=lambda x: x[1], reverse=True):
            if score >= threshold:
                return grade
        return 'F'

    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate recommendations based on scores"""
        recommendations = []

        # Check vulnerability score
        if self.scores['vulnerability'] < 70:
            recommendations.append({
                'category': 'vulnerability',
                'priority': 'high',
                'title': 'Address High and Medium Severity Vulnerabilities',
                'description': 'Focus on fixing high and medium severity vulnerabilities first to improve your security posture.'
            })

        # Check code quality score
        if self.scores['code_quality'] < 70:
            if 'complexity' in self.scores and self.scores['complexity'] < 60:
                recommendations.append({
                    'category': 'code_quality',
                    'priority': 'medium',
                    'title': 'Reduce Code Complexity',
                    'description': 'Refactor complex methods and classes to improve maintainability and reduce security risks.'
                })

            if 'duplication' in self.scores and self.scores['duplication'] < 60:
                recommendations.append({
                    'category': 'code_quality',
                    'priority': 'medium',
                    'title': 'Reduce Code Duplication',
                    'description': 'Eliminate duplicated code to improve maintainability and ensure consistent security practices.'
                })

        # Check security practices score
        if self.scores['security_practices'] < 70:
            recommendations.append({
                'category': 'security_practices',
                'priority': 'high',
                'title': 'Improve Input Validation and Output Encoding',
                'description': 'Implement proper input validation and output encoding to prevent injection attacks.'
            })

        # Check testing score
        if self.scores['testing'] < 60:
            recommendations.append({
                'category': 'testing',
                'priority': 'medium',
                'title': 'Increase Test Coverage',
                'description': 'Add more tests, especially security-focused tests, to catch vulnerabilities earlier.'
            })

        # Check dependencies score
        if self.scores['dependencies'] < 70:
            recommendations.append({
                'category': 'dependencies',
                'priority': 'high',
                'title': 'Update Vulnerable Dependencies',
                'description': 'Update or replace dependencies with known vulnerabilities to reduce risk.'
            })

        return recommendations

def calculate_security_posture(repo_path: str, repo_name: str, scan_results: Dict[str, Any],
                              metrics: Dict[str, Any], taint_results: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate security posture score for a repository"""
    scorer = SecurityPostureScorer(repo_path, repo_name)
    return scorer.calculate_score(scan_results, metrics, taint_results)
