from flask import Flask, flash, redirect, url_for, request, jsonify, render_template, session, send_file
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from utils.repo_visualizer import get_repo_structure, generate_mermaid_diagram
from utils.metrics_analyzer import extract_metrics_from_scan, calculate_file_risks
from utils.taint_analyzer import run_taint_analysis
from utils.security_posture import calculate_security_posture
from utils.typesafe_triage import triage_findings
from utils.dependency_scanner import run_osv_scan
from utils.license_analyzer import analyze_licenses
from utils.external_scanners import SCANNERS, classify_bandit, classify_pylint
from utils import scanner_status
import logging, requests, json, git, shutil, subprocess, os, pdfkit, tempfile, time, threading, sys, urllib.parse
from ci_integration import ci_integration_app, trigger_ci_pipeline
from utils.binary_analyzer import analyze_binary_with_angr, analyze_binary_with_ghidra, analyze_binary_with_radare2, get_binary_analysis_tools
# Import analyze_binary_with_capstone conditionally to avoid import errors
try:
    from utils.binary_analyzer import analyze_binary_with_capstone
    CAPSTONE_AVAILABLE = True
except (ImportError, SyntaxError):
    CAPSTONE_AVAILABLE = False
from config import get_config

# Load the environment variables from the .env file
load_dotenv()

# Create Flask application
app = Flask(__name__)

# Load configuration based on environment
config = get_config()
app.config.from_object(config)
app.config['APP_NAME'] = 'CodeBlue'
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'a_default_secret_key_if_none_is_found')

db = SQLAlchemy(app)

# Define your models here
class ExampleModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

class ToolResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    repo_name = db.Column(db.String(100), nullable=False)
    tool_name = db.Column(db.String(50), nullable=False)
    result = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))

# Define the MetricsHistory model for tracking metrics over time
class MetricsHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    repo_name = db.Column(db.String(100), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    # Security metrics
    high_severity_issues = db.Column(db.Integer, default=0)
    medium_severity_issues = db.Column(db.Integer, default=0)
    low_severity_issues = db.Column(db.Integer, default=0)
    total_issues = db.Column(db.Integer, default=0)

    # Code quality metrics
    code_complexity = db.Column(db.Float, default=0.0)
    code_duplication = db.Column(db.Float, default=0.0)
    maintainability_index = db.Column(db.Float, default=0.0)

    # Additional metrics
    dependencies_with_vulnerabilities = db.Column(db.Integer, default=0)
    lines_of_code = db.Column(db.Integer, default=0)
    test_coverage = db.Column(db.Float, default=0.0)

    def __repr__(self):
        return f"<MetricsHistory {self.repo_name} {self.scan_date}>"

# Define the FileRisk model for storing risk data for heat maps
class FileRisk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    repo_name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    # Risk scores (0-100 scale)
    total_risk = db.Column(db.Float, default=0.0)
    security_risk = db.Column(db.Float, default=0.0)
    complexity_risk = db.Column(db.Float, default=0.0)
    churn_risk = db.Column(db.Float, default=0.0)

    # Raw metrics
    issue_count = db.Column(db.Integer, default=0)
    cyclomatic_complexity = db.Column(db.Float, default=0.0)
    cognitive_complexity = db.Column(db.Float, default=0.0)
    lines_changed_last_month = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<FileRisk {self.repo_name} {self.file_path}>"

# Define the TaintAnalysisResult model for storing taint analysis results
class TaintAnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    repo_name = db.Column(db.String(100), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    # Summary metrics
    total_sources = db.Column(db.Integer, default=0)
    total_sinks = db.Column(db.Integer, default=0)
    total_sanitizers = db.Column(db.Integer, default=0)
    total_paths = db.Column(db.Integer, default=0)
    high_risk_paths = db.Column(db.Integer, default=0)
    medium_risk_paths = db.Column(db.Integer, default=0)
    low_risk_paths = db.Column(db.Integer, default=0)

    # Detailed results stored as JSON
    detailed_results = db.Column(db.Text, default='{}')

    def __repr__(self):
        return f"<TaintAnalysisResult {self.repo_name} {self.scan_date}>"

# Define the SecurityPostureScore model for storing security posture scores
class SecurityPostureScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    repo_name = db.Column(db.String(100), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    # Overall score and grade
    overall_score = db.Column(db.Float, default=0.0)
    grade = db.Column(db.String(2), default='F')

    # Category scores
    vulnerability_score = db.Column(db.Float, default=0.0)
    code_quality_score = db.Column(db.Float, default=0.0)
    security_practices_score = db.Column(db.Float, default=0.0)
    testing_score = db.Column(db.Float, default=0.0)
    dependencies_score = db.Column(db.Float, default=0.0)

    # Recommendations stored as JSON
    recommendations = db.Column(db.Text, default='[]')

    def __repr__(self):
        return f"<SecurityPostureScore {self.repo_name} {self.scan_date} ({self.grade})>"

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# Create a file handler to log to a file
file_handler = logging.FileHandler('bluescrub_debug.log')
file_handler.setLevel(logging.DEBUG)
# Create a formatter for the file handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
# Add the file handler to the root logger
logging.getLogger('').addHandler(file_handler)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/scrape', methods=['GET', 'POST'])
def scrape():
    """Redirect to the main page"""
    # Keep the POST functionality for form submissions from the main page
    if request.method == 'POST':
        tags = request.form.get('tags', '')
        github_url = request.form.get('github_url', '')
        local_path = request.form.get('local_path', '')
        network_path = request.form.get('network_path', '')

        logging.debug(f"Received form data - Tags: {tags}, GitHub URL: {github_url}, Local Path: {local_path}, Network Path: {network_path}")

        repositories = []

        try:
            if tags:
                repositories = get_repositories_from_github(tags)
                logging.debug(f"Repositories found with tags '{tags}': {repositories}")
            elif github_url:
                repositories = [get_detailed_info(github_url)]
                logging.debug(f"Repository found with URL '{github_url}': {repositories}")
            elif local_path or network_path:
                path = os.path.abspath(local_path or network_path)
                logging.debug(f"Checking path: {path}")
                if os.path.isdir(path):
                    logging.debug(f"Path '{path}' is a directory")

                    # First, check if the specified path itself is a repository or project directory
                    if os.path.isdir(path):
                        # Create a basic info object for the directory
                        repo_info = {
                            'html_url': path,
                            'name': os.path.basename(path),
                            'description': f"Local directory: {path}",
                            'issues_count': 'N/A',
                            'pulls_count': 'N/A',
                            'last_updated': datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M:%S'),
                            'stars': 'N/A',
                            'forks': 'N/A',
                            'watchers': 'N/A',
                            'language': 'N/A'
                        }
                        repositories.append(repo_info)
                        logging.debug(f"Added directory as repository: {path}")

                    # Also look for Git repositories within the directory
                    repo_urls = []
                    for root, dirs, files in os.walk(path):
                        if '.git' in dirs:
                            repo_url = root
                            repo_urls.append(repo_url)
                            logging.debug(f"Found git repository at: {repo_url}")

                    for repo_url in repo_urls:
                        if repo_url != path:  # Avoid duplicating the main directory if it's also a git repo
                            repositories.append(get_local_repo_info(repo_url))
                            logging.debug(f"Repository found at local/network path '{repo_url}': {repositories[-1]}")
                else:
                    logging.warning(f"Path '{path}' does not exist or is not a directory")

                    # Try to find the directory in common locations
                    home_dir = os.path.expanduser('~')
                    alternative_paths = [
                        os.path.join(home_dir, 'Downloads', 'BlueSpunge 2 4', os.path.basename(path)),
                        os.path.join(home_dir, 'Downloads', os.path.basename(path)),
                        os.path.join(home_dir, 'Documents', os.path.basename(path)),
                        os.path.join(home_dir, 'Desktop', os.path.basename(path))
                    ]

                    # Check if any of the alternative paths exist
                    for alt_path in alternative_paths:
                        if os.path.isdir(alt_path):
                            logging.info(f"Found alternative path: {alt_path}")
                            # Create a basic info object for the directory
                            repo_info = {
                                'html_url': alt_path,
                                'name': os.path.basename(alt_path),
                                'description': f"Local directory: {alt_path}",
                                'issues_count': 'N/A',
                                'pulls_count': 'N/A',
                                'last_updated': datetime.fromtimestamp(os.path.getmtime(alt_path)).strftime('%Y-%m-%d %H:%M:%S'),
                                'stars': 'N/A',
                                'forks': 'N/A',
                                'watchers': 'N/A',
                                'language': 'N/A'
                            }
                            repositories.append(repo_info)
                            return render_template('results.html', repositories=repositories)

                    # If we couldn't find an alternative, create the directory in Untested
                    try:
                        # Get the base name of the path (the directory name)
                        dir_name = os.path.basename(path)

                        # Create the directory in the Untested folder
                        untested_dir = os.path.join(os.getcwd(), 'Untested')
                        os.makedirs(untested_dir, exist_ok=True)  # Make sure Untested exists

                        new_dir_path = os.path.join(untested_dir, dir_name)
                        os.makedirs(new_dir_path, exist_ok=True)

                        logging.info(f"Created new directory: {new_dir_path}")

                        # Create a basic info object for the new directory
                        repo_info = {
                            'html_url': new_dir_path,
                            'name': dir_name,
                            'description': f"Newly created directory: {new_dir_path}",
                            'issues_count': 'N/A',
                            'pulls_count': 'N/A',
                            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'stars': 'N/A',
                            'forks': 'N/A',
                            'watchers': 'N/A',
                            'language': 'N/A'
                        }
                        repositories.append(repo_info)

                        flash(f"Directory '{dir_name}' was created in the Untested folder.", "info")
                        return render_template('results.html', repositories=repositories)
                    except Exception as e:
                        logging.error(f"Error creating directory: {str(e)}")
                        return render_template('error.html', message=f"Could not create directory: {str(e)}")

            return render_template('results.html', repositories=repositories)
        except Exception as e:
            logging.error(f"Error during scraping: {str(e)}", exc_info=True)
            return render_template('error.html', message="An error occurred during scraping.")
    else:
        # For GET requests, redirect to the main page
        return redirect(url_for('index'))

def get_local_repo_info(repo_path):
    """Get basic info from a local Git repository."""
    try:
        repo = git.Repo(repo_path)
        return {
            'html_url': repo_path,
            'name': os.path.basename(repo_path),
            'issues_count': 'N/A',  # Local repos might not have issues information
            'pulls_count': 'N/A',  # Local repos might not have pull request information
            'last_updated': datetime.fromtimestamp(repo.head.commit.committed_date).strftime('%Y-%m-%d %H:%M:%S'),
            'stars': 'N/A',  # Local repos don't have stars
            'forks': 'N/A',  # Local repos don't have forks
            'watchers': 'N/A',  # Local repos don't have watchers
            'language': 'N/A'  # Local repos might not have language information readily available
        }
    except Exception as e:
        logging.error(f"Error retrieving info for local repository '{repo_path}': {str(e)}")
        return {
            'html_url': repo_path,
            'error': f"Failed to retrieve info for local repository: {str(e)}"
        }

@app.route('/review', methods=['GET', 'POST'])
def review_selected():
    if request.method == 'POST':
        repo_urls = request.form.getlist('repo_urls')
        detailed_info = []
        for url in repo_urls:
            if os.path.isdir(url):  # Check if it's a local directory
                info = get_local_repo_info(url)
            else:
                info = get_detailed_info(url)
            detailed_info.append(info)
        session['detailed_info'] = detailed_info  # Store in session
        return render_template('review.html', detailed_info=detailed_info)
    else:
        return render_template('review.html', detailed_info=session.get('detailed_info', []))

@app.route('/save_selected', methods=['POST'])
def save_selected():
    selected_urls = request.form.getlist('repo_urls')
    detailed_info = session.get('detailed_info', [])

    selected_repos = [repo for repo in detailed_info if repo['html_url'] in selected_urls]

    if not selected_repos:
        return render_template('review.html', detailed_info=detailed_info, message="No repositories were selected to save.")

    # Generate a filename based on the selected repositories
    base_filename = "_".join(repo['name'] for repo in selected_repos)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"{base_filename}_{timestamp}.json" if base_filename else f"default_filename_{timestamp}.json"

    safe_filename = secure_filename(filename)
    save_directory = 'saved_repositories'
    os.makedirs(save_directory, exist_ok=True)
    filepath = os.path.join(save_directory, safe_filename)

    with open(filepath, 'w') as f:
        json.dump(selected_repos, f, indent=4)

    return render_template('review.html', detailed_info=detailed_info, message=f"Selected repositories have been saved as {safe_filename}.")

@app.route('/scan_code', methods=['POST'])
def handle_scan_code():
    logging.info("=== Scan code request received ===")
    repo_url = request.form['repo_to_scan']
    logging.info(f"Repository URL from form: {repo_url}")

    # Always use the Untested directory for simplicity and consistency
    repo_name = os.path.basename(repo_url).replace('.git', '')
    logging.info(f"Repository name: {repo_name}")
    local_dir = os.path.join('Untested', repo_name)
    logging.info(f"Using directory: {local_dir}")

    # Log additional information about the directory
    if os.path.exists(local_dir):
        logging.info(f"Directory exists: {local_dir}")
        if os.path.isdir(local_dir):
            dir_contents = os.listdir(local_dir)
            logging.info(f"Directory contents: {dir_contents}")
            if not dir_contents:
                logging.warning(f"Directory is empty: {local_dir}")
        else:
            logging.warning(f"Path exists but is not a directory: {local_dir}")
    else:
        logging.warning(f"Directory does not exist: {local_dir}")
        # Create the directory
        os.makedirs(local_dir, exist_ok=True)
        logging.info(f"Created directory: {local_dir}")

    # Check if the repository needs to be populated first
    if not os.path.exists(local_dir) or not os.listdir(local_dir):
        logging.warning(f"Directory {local_dir} does not exist or is empty")

        if repo_url.startswith('http://') or repo_url.startswith('https://'):
            # GitHub (or other remote) URL: clone it
            logging.info(f"Attempting to clone repository: {repo_url}")
            try:
                if os.path.exists(local_dir):
                    shutil.rmtree(local_dir)
                os.makedirs(local_dir, exist_ok=True)
                git.Repo.clone_from(repo_url, local_dir)
                logging.info(f"Repository cloned successfully to {local_dir}")
            except Exception as e:
                logging.error(f"Failed to clone repository: {str(e)}")
                return render_template('scan_results.html',
                                      result={'success': False,
                                             'error': f"Failed to clone repository: {str(e)}",
                                             'output': "No analysis performed. Failed to clone repository.",
                                             'repo_name': repo_name,
                                             'repo_path': local_dir},
                                      analysis_content="No analysis results found. Please clone the repository first.")
        elif os.path.isdir(repo_url) and os.path.abspath(repo_url) != os.path.abspath(local_dir):
            # Local or network filesystem path (from /scrape's local_path or
            # network_path fields): copy it into the scan working directory,
            # mirroring how a remote URL is cloned there.
            logging.info(f"Copying local/network project into scan directory: {repo_url} -> {local_dir}")
            try:
                if os.path.exists(local_dir):
                    shutil.rmtree(local_dir)
                shutil.copytree(repo_url, local_dir)
                logging.info(f"Project copied successfully to {local_dir}")
            except Exception as e:
                logging.error(f"Failed to copy project from {repo_url}: {str(e)}")
                return render_template('scan_results.html',
                                      result={'success': False,
                                             'error': f"Failed to copy project from {repo_url}: {str(e)}",
                                             'output': "No analysis performed. Failed to access the local/network path.",
                                             'repo_name': repo_name,
                                             'repo_path': local_dir},
                                      analysis_content="No analysis results found. Please check the path and try again.")
        else:
            # Not a remote URL, and not a directory this process can see.
            logging.error(f"Cannot scan '{repo_url}': not a valid URL and not an accessible local/network path")
            return render_template('scan_results.html',
                                  result={'success': False,
                                         'error': f"'{repo_url}' is not a reachable local/network path or repository URL.",
                                         'output': "No analysis performed. The path may not exist, or may not be "
                                                    "accessible from inside this server's filesystem (for example, "
                                                    "a network share that isn't mounted here).",
                                         'repo_name': repo_name,
                                         'repo_path': local_dir},
                                  analysis_content="No analysis results found. Please check the path and try again.")

    # Run the security analysis
    scan_result = run_bluescrub(local_dir, repo_name)

    # Log the scan result
    logging.debug(f"Scan result: {scan_result}")

    # Get the analysis output
    analysis_output_path = os.path.join(local_dir, 'analysis_results', f'{repo_name}_analysis_output.html')
    logging.debug(f"Looking for analysis output at: {analysis_output_path}")

    try:
        with open(analysis_output_path, 'r') as file:
            analysis_content = file.read()
            logging.debug("Analysis content loaded successfully")
    except FileNotFoundError:
        logging.error(f"Analysis output file not found: {analysis_output_path}")
        analysis_content = """
        <html>
        <head>
            <title>No Analysis Results</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .error { color: red; }
            </style>
        </head>
        <body>
            <h1 class="error">No Analysis Results Found</h1>
            <p>The analysis output file could not be found. This may be because:</p>
            <ul>
                <li>The repository has not been cloned properly</li>
                <li>The analysis failed to run</li>
                <li>The output file was not created</li>
            </ul>
            <p>Please try cloning the repository again and then run the scan.</p>
        </body>
        </html>
        """

    return render_template('scan_results.html', result=scan_result, analysis_content=analysis_content)

def run_bluescrub(directory, repo_name):
    logging.info(f"=== Starting security analysis for {repo_name} in directory {directory} ===")
    try:
        # Check if directory exists
        logging.debug(f"Checking if directory {directory} exists")
        if not os.path.exists(directory):
            logging.warning(f"Directory {directory} does not exist, creating it")
            os.makedirs(directory, exist_ok=True)
            logging.error(f"Directory {directory} was created but is empty")
            return {
                'success': False,
                'error': f"Directory {directory} does not exist or is empty. Please clone the repository first.",
                'output': "No analysis performed. Directory is empty.",
                'repo_name': repo_name,
                'repo_path': directory
            }

        # Check if directory is empty
        logging.debug(f"Checking contents of directory {directory}")

        # Filter out hidden files and directories (like .git)
        dir_contents = [f for f in os.listdir(directory) if not f.startswith('.') and f != 'analysis_results']
        logging.debug(f"Directory contents (excluding hidden files): {dir_contents}")

        # If the only files are hidden files or analysis_results, consider it empty
        if not dir_contents:
            logging.warning(f"Directory {directory} exists but is empty")

            # Create a simple analysis report even if the directory is empty
            analysis_results_dir = os.path.join(directory, 'analysis_results')
            logging.debug(f"Creating analysis results directory: {analysis_results_dir}")
            os.makedirs(analysis_results_dir, exist_ok=True)

            # Generate a simple HTML report
            html_output = f"""
            <html>
            <head>
                <title>Empty Directory Analysis for {repo_name}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; }}
                    h1, h2 {{ color: #333; }}
                    .warning {{ color: orange; }}
                    .error {{ color: red; }}
                    .success {{ color: green; }}
                </style>
            </head>
            <body>
                <h1>Empty Directory Analysis for {repo_name}</h1>
                <div class="warning">
                    <h2>Warning: Empty Directory</h2>
                    <p>The directory {directory} is empty. No analysis could be performed.</p>
                    <p>Please clone a repository into this directory or select a different repository.</p>
                </div>
            </body>
            </html>
            """

            # Save HTML report
            output_path = os.path.join(analysis_results_dir, f'{repo_name}_analysis_output.html')
            logging.debug(f"Saving HTML report to: {output_path}")
            try:
                with open(output_path, 'w') as f:
                    f.write(html_output)
                logging.info(f"HTML report saved successfully to {output_path}")
            except Exception as e:
                logging.error(f"Error saving HTML report: {str(e)}")
                logging.exception("Exception details:")

            return {
                'success': True,
                'details': 'Analysis completed. Directory is empty.',
                'output': "Directory is empty. No code to analyze.",
                'repo_name': repo_name,
                'repo_path': directory
            }

        # Create analysis_results directory if it doesn't exist
        analysis_results_dir = os.path.join(directory, 'analysis_results')
        logging.debug(f"Creating analysis results directory: {analysis_results_dir}")
        os.makedirs(analysis_results_dir, exist_ok=True)

        # Run basic security checks
        logging.info(f"Starting security analysis for {repo_name}")
        output = f"Security analysis for {repo_name}:\n\n"

        # Run Python security tools if they exist
        try:
            # Every scanner subprocess below is pointed at `directory` via an
            # explicit cwd= argument. The process's own current directory is
            # deliberately left at BlueScrub's own root throughout - not
            # chdir()'d into `directory` - because on Windows, both
            # shutil.which() and CreateProcess's own executable search check
            # the *process's* current directory before PATH. If the process
            # cwd were the (untrusted) scanned repository, a repo that ships
            # e.g. a same-named bandit.exe/eslint.cmd in its root would get
            # resolved and executed instead of the real installed tool. See
            # tests/test_scanner_execution_boundary.py.
            logging.debug(f"Scanning directory: {directory} (process cwd stays {os.getcwd()})")

            # Run bandit (Python security scanner)
            #
            # A ToolResult row is recorded on every attempt - PASS, FINDINGS,
            # UNAVAILABLE, or ERROR - not just the success path, so a scanner
            # that errored (or was never installed) is never indistinguishable
            # from one that was never run at all, or from a clean scan.
            # classify_bandit() interprets Bandit's own documented exit codes
            # (0=clean, 1=findings, 2=Bandit-internal failure) rather than
            # assuming a generic 0/1 convention; the raw stdout is preserved
            # in the envelope's _output field either way, matching the
            # text-parsing fallback /security_issues already has for
            # tool_name == 'bandit'.
            logging.info("Running Bandit (Python security scanner)")
            output += "Running Bandit (Python security scanner)...\n"
            try:
                # Add a timeout to prevent the process from running indefinitely
                bandit_result = subprocess.run(['bandit', '-r', '.'], capture_output=True, text=True, timeout=300, cwd=directory)  # 5 minute timeout
                logging.debug(f"Bandit return code: {bandit_result.returncode}")
                logging.debug(f"Bandit stdout length: {len(bandit_result.stdout)}")
                logging.debug(f"Bandit stderr: {bandit_result.stderr}")
                output += bandit_result.stdout + "\n\n"
                b_status, b_count = classify_bandit(bandit_result.returncode, bandit_result.stdout)
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='bandit',
                    result=scanner_status.build_result(
                        b_status, f"bandit: {b_status}", exit_code=bandit_result.returncode,
                        findings_count=b_count, output=bandit_result.stdout or '',
                    )
                ))
            except FileNotFoundError as e:
                error_msg = f"Bandit is not installed or not on PATH: {str(e)}"
                logging.error(error_msg)
                output += error_msg + "\n\n"
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='bandit',
                    result=scanner_status.build_result(scanner_status.UNAVAILABLE, error_msg)
                ))
            except Exception as e:
                error_msg = f"Error running Bandit: {str(e)}"
                logging.error(error_msg)
                output += error_msg + "\n\n"
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='bandit',
                    result=scanner_status.build_result(scanner_status.ERROR, error_msg)
                ))

            # Run pylint (Python linter). classify_pylint() interprets
            # pylint's documented bitmask exit code deliberately (see its
            # docstring) rather than treating every non-zero code as findings.
            #
            # --recursive=y is required: pylint's --recursive defaults to
            # False, so a bare '.' is treated as a single package needing
            # its own __init__.py rather than "scan this directory tree" -
            # without it, pylint fails with the same F0010 parse-error on
            # every single scan regardless of the target code's actual
            # content (confirmed against a real pylint 3.2.2 install; this
            # invocation had never actually been exercised against a working
            # pylint install before Gate 4).
            logging.info("Running Pylint (Python linter)")
            output += "Running Pylint (Python linter)...\n"
            try:
                # Add a timeout to prevent the process from running indefinitely
                pylint_result = subprocess.run(['pylint', '--output-format=text', '--recursive=y', '.'], capture_output=True, text=True, timeout=300, cwd=directory)  # 5 minute timeout
                logging.debug(f"Pylint return code: {pylint_result.returncode}")
                logging.debug(f"Pylint stdout length: {len(pylint_result.stdout)}")
                logging.debug(f"Pylint stderr: {pylint_result.stderr}")
                output += pylint_result.stdout + "\n\n"
                p_status, p_count = classify_pylint(pylint_result.returncode, pylint_result.stdout)
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='pylint',
                    result=scanner_status.build_result(
                        p_status, f"pylint: {p_status}", exit_code=pylint_result.returncode,
                        findings_count=p_count, output=pylint_result.stdout or '',
                    )
                ))
            except FileNotFoundError as e:
                error_msg = f"Pylint is not installed or not on PATH: {str(e)}"
                logging.error(error_msg)
                output += error_msg + "\n\n"
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='pylint',
                    result=scanner_status.build_result(scanner_status.UNAVAILABLE, error_msg)
                ))
            except Exception as e:
                error_msg = f"Error running Pylint: {str(e)}"
                logging.error(error_msg)
                output += error_msg + "\n\n"
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='pylint',
                    result=scanner_status.build_result(scanner_status.ERROR, error_msg)
                ))

            # Run OSV-Scanner (multi-ecosystem dependency vulnerability scan).
            # run_osv_scan() already classifies internally (see
            # utils/dependency_scanner.py) and never raises; the except below
            # is a last-resort safety net, not the primary status path.
            logging.info("Running OSV-Scanner (dependency vulnerability scan)")
            output += "Running OSV-Scanner (Software Composition Analysis)...\n"
            try:
                osv_result = run_osv_scan(directory)
                output += osv_result['summary_text']
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='osv-scanner',
                    result=scanner_status.build_result(
                        osv_result['status'], f"osv-scanner: {osv_result['status']}",
                        findings_count=len(osv_result['findings']) or None,
                        output=osv_result['summary_text'], findings=osv_result['findings'],
                    )
                ))
            except Exception as e:
                error_msg = f"Error running OSV-Scanner: {str(e)}"
                logging.error(error_msg)
                logging.exception("OSV-Scanner error details:")
                output += error_msg + "\n\n"
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='osv-scanner',
                    result=scanner_status.build_result(scanner_status.ERROR, error_msg)
                ))

            # Run license compliance check (SPDX headers + declared repo
            # license). Pure Python, no executable - so UNAVAILABLE never
            # applies to it; only PASS/FINDINGS (from analyze_licenses()'s
            # own findings count) and ERROR (any exception) do.
            logging.info("Running license compliance check")
            output += "Running License Check...\n"
            try:
                license_result = analyze_licenses(directory)
                output += license_result['summary_text']
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='license-check',
                    result=scanner_status.build_result(
                        license_result['status'], f"license-check: {license_result['status']}",
                        findings_count=len(license_result['findings']) or None,
                        output=license_result['summary_text'], findings=license_result['findings'],
                    )
                ))
            except Exception as e:
                error_msg = f"Error running license check: {str(e)}"
                logging.error(error_msg)
                logging.exception("License check error details:")
                output += error_msg + "\n\n"
                db.session.add(ToolResult(
                    repo_name=repo_name,
                    tool_name='license-check',
                    result=scanner_status.build_result(scanner_status.ERROR, error_msg)
                ))

            # Run the remaining external scanners (Safety, Semgrep, Checkov,
            # ESLint, JSHint, TruffleHog, TFSec, GitLeaks). Each classifies
            # and degrades internally (see utils/external_scanners.py) and
            # never raises; the except below is a last-resort safety net.
            for tool_name, scanner_fn in SCANNERS.items():
                logging.info(f"Running {tool_name}")
                output += f"Running {tool_name}...\n"
                try:
                    scan_result = scanner_fn(directory)
                    output += scan_result['display_output'] + "\n\n"
                    db.session.add(ToolResult(
                        repo_name=repo_name,
                        tool_name=tool_name,
                        result=scan_result['result_json']
                    ))
                except Exception as e:
                    error_msg = f"Error running {tool_name}: {str(e)}"
                    logging.error(error_msg)
                    logging.exception(f"{tool_name} error details:")
                    output += error_msg + "\n\n"
                    db.session.add(ToolResult(
                        repo_name=repo_name,
                        tool_name=tool_name,
                        result=scanner_status.build_result(scanner_status.ERROR, error_msg)
                    ))
        except Exception as e:
            error_msg = f"Error running Python security tools: {str(e)}"
            logging.error(error_msg)
            logging.exception("Exception details:")
            output += error_msg + "\n\n"

        # Initialize variables for taint analysis and security posture
        taint_results = {'summary': {}}
        posture_score = {
            'grade': 'F',
            'overall_score': 0,
            'category_scores': {
                'vulnerability': 0,
                'code_quality': 0,
                'security_practices': 0,
                'testing': 0,
                'dependencies': 0
            },
            'recommendations': []
        }

        logging.info(f"=== Security analysis for {repo_name} completed successfully ===")

        # Run taint analysis
        logging.info(f"Running taint analysis for {repo_name}")
        output += "Running Taint Analysis...\n"
        try:
            # Use a simple timeout approach that works in all threads
            import threading
            import time

            # Default empty results in case of timeout
            taint_results = {
                'summary': {
                    'total_paths': 0,
                    'high_risk_paths': 0,
                    'medium_risk_paths': 0,
                    'low_risk_paths': 0
                },
                'paths': {}
            }

            # Flag to indicate if analysis completed
            analysis_completed = False

            # Function to run the analysis
            def run_analysis():
                nonlocal taint_results, analysis_completed
                try:
                    taint_results = run_taint_analysis(directory)
                    analysis_completed = True
                except Exception as e:
                    logging.error(f"Error in taint analysis thread: {str(e)}")

            # Start the analysis in a separate thread
            analysis_thread = threading.Thread(target=run_analysis)
            analysis_thread.daemon = True
            analysis_thread.start()

            # Wait for the analysis to complete with a timeout
            timeout = 300  # 5 minutes
            start_time = time.time()
            while not analysis_completed and time.time() - start_time < timeout:
                time.sleep(1)

            if not analysis_completed:
                logging.error("Taint analysis timed out after 5 minutes")
                output += "Taint analysis timed out after 5 minutes. Results may be incomplete.\n\n"
            else:
                logging.debug(f"Taint analysis results: {taint_results}")

            # Add summary to output
            summary = taint_results.get('summary', {})
            output += f"Found {summary.get('total_paths', 0)} potential taint flow paths:\n"
            output += f"  - High Risk: {summary.get('high_risk_paths', 0)}\n"
            output += f"  - Medium Risk: {summary.get('medium_risk_paths', 0)}\n"
            output += f"  - Low Risk: {summary.get('low_risk_paths', 0)}\n\n"

            # Save taint analysis results to database
            taint_record = TaintAnalysisResult(
                repo_name=repo_name,
                total_sources=summary.get('total_sources', 0),
                total_sinks=summary.get('total_sinks', 0),
                total_sanitizers=summary.get('total_sanitizers', 0),
                total_paths=summary.get('total_paths', 0),
                high_risk_paths=summary.get('high_risk_paths', 0),
                medium_risk_paths=summary.get('medium_risk_paths', 0),
                low_risk_paths=summary.get('low_risk_paths', 0),
                detailed_results=json.dumps(taint_results.get('paths', {}))
            )
            db.session.add(taint_record)

        except Exception as e:
            error_msg = f"Error running taint analysis: {str(e)}"
            logging.error(error_msg)
            logging.exception("Taint analysis error details:")
            output += error_msg + "\n\n"
            taint_results = {'summary': {}}  # Empty results for posture scoring

        # Extract metrics for dashboard
        try:
            logging.info(f"Extracting metrics for dashboard from {repo_name}")
            metrics = extract_metrics_from_scan(repo_name, {
                'success': True,
                'output': output,
                'repo_path': directory
            }, directory)

            # Save metrics to database
            metrics_record = MetricsHistory(
                repo_name=metrics['repo_name'],
                scan_date=metrics['scan_date'],
                high_severity_issues=metrics['high_severity_issues'],
                medium_severity_issues=metrics['medium_severity_issues'],
                low_severity_issues=metrics['low_severity_issues'],
                total_issues=metrics['total_issues'],
                code_complexity=metrics['code_complexity'],
                code_duplication=metrics['code_duplication'],
                maintainability_index=metrics['maintainability_index'],
                dependencies_with_vulnerabilities=metrics['dependencies_with_vulnerabilities'],
                lines_of_code=metrics['lines_of_code'],
                test_coverage=metrics['test_coverage']
            )
            db.session.add(metrics_record)

            # Calculate and save file risk data for heat map
            logging.info(f"Calculating file risks for {repo_name}")
            file_risks = calculate_file_risks(repo_name, directory)
            for risk_data in file_risks:
                file_risk = FileRisk(
                    repo_name=risk_data['repo_name'],
                    file_path=risk_data['file_path'],
                    scan_date=risk_data['scan_date'],
                    total_risk=risk_data['total_risk'],
                    security_risk=risk_data['security_risk'],
                    complexity_risk=risk_data['complexity_risk'],
                    churn_risk=risk_data['churn_risk'],
                    issue_count=risk_data['issue_count'],
                    cyclomatic_complexity=risk_data['cyclomatic_complexity'],
                    cognitive_complexity=risk_data['cognitive_complexity'],
                    lines_changed_last_month=risk_data['lines_changed_last_month']
                )
                db.session.add(file_risk)

            # Calculate security posture score
            logging.info(f"Calculating security posture score for {repo_name}")
            scan_results = {'output': output}
            posture_score = calculate_security_posture(directory, repo_name, scan_results, metrics, taint_results)

            # Add posture score to output
            output += f"\nSecurity Posture Score: {posture_score['overall_score']:.1f}/100 (Grade: {posture_score['grade']})\n"
            output += "Category Scores:\n"
            output += f"  - Vulnerability: {posture_score['category_scores']['vulnerability']:.1f}/100\n"
            output += f"  - Code Quality: {posture_score['category_scores']['code_quality']:.1f}/100\n"
            output += f"  - Security Practices: {posture_score['category_scores']['security_practices']:.1f}/100\n"
            output += f"  - Testing: {posture_score['category_scores']['testing']:.1f}/100\n"
            output += f"  - Dependencies: {posture_score['category_scores']['dependencies']:.1f}/100\n"

            # Save posture score to database
            posture_record = SecurityPostureScore(
                repo_name=repo_name,
                overall_score=posture_score['overall_score'],
                grade=posture_score['grade'],
                vulnerability_score=posture_score['category_scores']['vulnerability'],
                code_quality_score=posture_score['category_scores']['code_quality'],
                security_practices_score=posture_score['category_scores']['security_practices'],
                testing_score=posture_score['category_scores']['testing'],
                dependencies_score=posture_score['category_scores']['dependencies'],
                recommendations=json.dumps(posture_score['recommendations'])
            )
            db.session.add(posture_record)

            db.session.commit()
            logging.info(f"Metrics, file risks, and security posture score saved to database for {repo_name}")
        except Exception as metrics_error:
            logging.error(f"Error saving metrics: {str(metrics_error)}")
            logging.exception("Metrics error details:")
            # Continue even if metrics extraction fails

        # Generate HTML report after all calculations are done
        # Build the HTML template using string concatenation instead of f-strings to avoid format specifier issues
        html_output = """
        <html>
        <head>
            <title>Security Analysis for """ + repo_name + """</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; }
                h1, h2, h3 { color: #333; }
                .warning { color: orange; }
                .error { color: red; }
                .success { color: green; }
                .grade { font-size: 2em; font-weight: bold; padding: 10px; border-radius: 50%; width: 50px; height: 50px; text-align: center; line-height: 50px; display: inline-block; }
                .grade-a { background-color: #28a745; color: white; }
                .grade-b { background-color: #5cb85c; color: white; }
                .grade-c { background-color: #f0ad4e; color: white; }
                .grade-d { background-color: #d9534f; color: white; }
                .grade-f { background-color: #dc3545; color: white; }
                .score-card { border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }
                .score-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
                .category-scores { display: flex; flex-wrap: wrap; }
                .category { flex: 1; min-width: 150px; margin: 5px; }
                .category h4 { margin-top: 0; }
                .progress { height: 20px; background-color: #f5f5f5; border-radius: 4px; overflow: hidden; }
                .progress-bar { height: 100%; color: white; text-align: center; line-height: 20px; }
                .taint-summary { margin-top: 20px; }
                .taint-paths { margin-top: 10px; }
                .recommendations { margin-top: 20px; }
                .recommendation { border-left: 4px solid #007bff; padding-left: 15px; margin-bottom: 10px; }
                .priority-high { border-left-color: #dc3545; }
                .priority-medium { border-left-color: #f0ad4e; }
                .priority-low { border-left-color: #5cb85c; }
            </style>
        </head>
        <body>
            <h1>Security Analysis Report for """ + repo_name + """</h1>

            <!-- Security Posture Score Section -->
            <div class="score-card">
                <div class="score-header">
                    <div>
                        <h2>Security Posture Score</h2>
                        <p>Overall assessment of the repository's security posture</p>
                    </div>
                    <div class="grade grade-""" + (posture_score['grade'][0].lower() if 'grade' in posture_score else 'f') + """">
                        """ + (posture_score['grade'] if 'grade' in posture_score else 'F') + """
                    </div>
                </div>

                <div class="category-scores">
                    <div class="category">
                        <h4>Vulnerability</h4>
                        <div class="progress">
                            <div class="progress-bar" style="width: """ + str(posture_score['category_scores']['vulnerability'] if 'category_scores' in posture_score else 0) + """%; background-color: """ + ('#28a745' if 'category_scores' in posture_score and posture_score['category_scores']['vulnerability'] >= 80 else '#5cb85c' if 'category_scores' in posture_score and posture_score['category_scores']['vulnerability'] >= 60 else '#f0ad4e' if 'category_scores' in posture_score and posture_score['category_scores']['vulnerability'] >= 40 else '#d9534f' if 'category_scores' in posture_score and posture_score['category_scores']['vulnerability'] >= 20 else '#dc3545') + """;">
                                """ + (f"{posture_score['category_scores']['vulnerability']:.1f}" if 'category_scores' in posture_score else "0") + """/100
                            </div>
                        </div>
                    </div>

                    <div class="category">
                        <h4>Code Quality</h4>
                        <div class="progress">
                            <div class="progress-bar" style="width: """ + str(posture_score['category_scores']['code_quality'] if 'category_scores' in posture_score else 0) + """%; background-color: """ + ('#28a745' if 'category_scores' in posture_score and posture_score['category_scores']['code_quality'] >= 80 else '#5cb85c' if 'category_scores' in posture_score and posture_score['category_scores']['code_quality'] >= 60 else '#f0ad4e' if 'category_scores' in posture_score and posture_score['category_scores']['code_quality'] >= 40 else '#d9534f' if 'category_scores' in posture_score and posture_score['category_scores']['code_quality'] >= 20 else '#dc3545') + """;">
                                """ + (f"{posture_score['category_scores']['code_quality']:.1f}" if 'category_scores' in posture_score else "0") + """/100
                            </div>
                        </div>
                    </div>

                    <div class="category">
                        <h4>Security Practices</h4>
                        <div class="progress">
                            <div class="progress-bar" style="width: """ + str(posture_score['category_scores']['security_practices'] if 'category_scores' in posture_score else 0) + """%; background-color: """ + ('#28a745' if 'category_scores' in posture_score and posture_score['category_scores']['security_practices'] >= 80 else '#5cb85c' if 'category_scores' in posture_score and posture_score['category_scores']['security_practices'] >= 60 else '#f0ad4e' if 'category_scores' in posture_score and posture_score['category_scores']['security_practices'] >= 40 else '#d9534f' if 'category_scores' in posture_score and posture_score['category_scores']['security_practices'] >= 20 else '#dc3545') + """;">
                                """ + (f"{posture_score['category_scores']['security_practices']:.1f}" if 'category_scores' in posture_score else "0") + """/100
                            </div>
                        </div>
                    </div>

                    <div class="category">
                        <h4>Testing</h4>
                        <div class="progress">
                            <div class="progress-bar" style="width: """ + str(posture_score['category_scores']['testing'] if 'category_scores' in posture_score else 0) + """%; background-color: """ + ('#28a745' if 'category_scores' in posture_score and posture_score['category_scores']['testing'] >= 80 else '#5cb85c' if 'category_scores' in posture_score and posture_score['category_scores']['testing'] >= 60 else '#f0ad4e' if 'category_scores' in posture_score and posture_score['category_scores']['testing'] >= 40 else '#d9534f' if 'category_scores' in posture_score and posture_score['category_scores']['testing'] >= 20 else '#dc3545') + """;">
                                """ + (f"{posture_score['category_scores']['testing']:.1f}" if 'category_scores' in posture_score else "0") + """/100
                            </div>
                        </div>
                    </div>

                    <div class="category">
                        <h4>Dependencies</h4>
                        <div class="progress">
                            <div class="progress-bar" style="width: """ + str(posture_score['category_scores']['dependencies'] if 'category_scores' in posture_score else 0) + """%; background-color: """ + ('#28a745' if 'category_scores' in posture_score and posture_score['category_scores']['dependencies'] >= 80 else '#5cb85c' if 'category_scores' in posture_score and posture_score['category_scores']['dependencies'] >= 60 else '#f0ad4e' if 'category_scores' in posture_score and posture_score['category_scores']['dependencies'] >= 40 else '#d9534f' if 'category_scores' in posture_score and posture_score['category_scores']['dependencies'] >= 20 else '#dc3545') + """;">
                                """ + (f"{posture_score['category_scores']['dependencies']:.1f}" if 'category_scores' in posture_score else "0") + """/100
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recommendations -->
                <div class="recommendations">
                    <h3>Recommendations</h3>
                    <div id="recommendations-placeholder"></div>
                </div>
            </div>

            <!-- Taint Analysis Section -->
            <div class="taint-summary">
                <h2>Taint Analysis Results</h2>
                <p>Analysis of how untrusted data flows through the application</p>

                <div class="taint-paths">
                    <h3>Potential Taint Flow Paths</h3>
                    <ul>
                        <li><strong>High Risk Paths:</strong> """ + str(taint_results['summary']['high_risk_paths'] if 'summary' in taint_results else 0) + """</li>
                        <li><strong>Medium Risk Paths:</strong> """ + str(taint_results['summary']['medium_risk_paths'] if 'summary' in taint_results else 0) + """</li>
                        <li><strong>Low Risk Paths:</strong> """ + str(taint_results['summary']['low_risk_paths'] if 'summary' in taint_results else 0) + """</li>
                    </ul>
                </div>
            </div>

            <h2>Analysis Results</h2>
            <pre>""" + output + """</pre>
        </body>
        </html>
        """

        # Save HTML report
        output_path = os.path.join(analysis_results_dir, f'{repo_name}_analysis_output.html')
        logging.debug(f"Saving HTML report to: {output_path}")
        try:
            # Generate recommendations HTML directly in the placeholder
            if 'recommendations' in posture_score and posture_score['recommendations']:
                recommendations_list = []
                for rec in posture_score['recommendations']:
                    rec_html = '<div class="recommendation priority-' + rec['priority'] + '">'
                    rec_html += '<h4>' + rec['title'] + '</h4>'
                    rec_html += '<p>' + rec['description'] + '</p>'
                    rec_html += '</div>'
                    recommendations_list.append(rec_html)
                recommendations_html = ''.join(recommendations_list)
            else:
                recommendations_html = '<p>No recommendations available.</p>'

            # Replace the placeholder with the actual content
            html_output = html_output.replace('<div id="recommendations-placeholder"></div>',
                                             '<div id="recommendations-placeholder">' + recommendations_html + '</div>')

            with open(output_path, 'w') as f:
                f.write(html_output)
            logging.info(f"HTML report saved successfully to {output_path}")
        except Exception as e:
            logging.error(f"Error saving HTML report: {str(e)}")
            logging.exception("Exception details:")

        return {
            'success': True,
            'details': 'Scan completed successfully. Check the results below.',
            'output': output,
            'repo_name': repo_name,
            'repo_path': directory
        }
    except Exception as e:
        error_msg = f"An error occurred during analysis: {str(e)}"
        logging.error(error_msg)
        logging.exception("Exception details:")
        return {
            'success': False,
            'error': str(e),
            'output': error_msg,
            'repo_name': repo_name,
            'repo_path': directory
        }

@app.route('/clone_repository', methods=['POST'])
def handle_clone_repository():
    data = request.get_json()
    repo_url = data.get('repo_to_clone')
    if not repo_url:
        return {'success': False, 'error': 'Repository URL not provided'}, 400

    local_dir = 'Untested'
    unique_dir = os.path.join(local_dir, os.path.basename(repo_url))
    if os.path.exists(unique_dir):
        shutil.rmtree(unique_dir)
    os.makedirs(unique_dir, exist_ok=True)

    try:
        git.Repo.clone_from(repo_url, unique_dir)
        return {'success': True, 'details': f'Repository cloned to {unique_dir}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}, 500

@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    try:
        data = request.get_json()
        html_content = data.get('html')

        if not html_content:
            return jsonify({'error': 'No HTML content provided'}), 400

        # Create a temporary directory for the PDF
        temp_dir = tempfile.mkdtemp()
        output_file = os.path.join(temp_dir, 'Security_Analysis_Report.pdf')

        # Configure pdfkit with wkhtmltopdf and options
        options = {
            'enable-local-file-access': '',  # Allow local file access
            'no-stop-slow-scripts': '',     # Do not stop slow scripts
            'debug-javascript': '',         # Enable debug Javascript
            'quiet': '',                    # Be less verbose
        }

        # Clean up the HTML content to make it more suitable for PDF generation
        # Remove scripts and other elements that might cause issues
        clean_html = html_content.replace('<script', '<!-- script').replace('</script>', '<!-- /script -->')

        # Add custom CSS for better PDF formatting
        pdf_style = """
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; white-space: pre-wrap; }
            h1, h2 { color: #333; }
            .card { border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px; }
            .card-body { padding: 15px; }
            .card-title { margin-bottom: 10px; font-weight: bold; }
            .container { width: 100%; max-width: 1200px; margin: 0 auto; }
            @page { size: A4; margin: 1cm; }
        </style>
        """

        # Insert the custom CSS into the HTML
        clean_html = clean_html.replace('</head>', f'{pdf_style}</head>')

        # Generate the PDF using pdfkit
        try:
            pdfkit.from_string(clean_html, output_file, options=options)
            logging.info(f"PDF generated successfully at {output_file}")
        except Exception as e:
            logging.error(f"Error generating PDF with pdfkit: {str(e)}")
            # Try a simpler approach if the first attempt fails
            simple_html = f"""
            <html>
            <head>
                <title>Security Analysis Report</title>
                {pdf_style}
            </head>
            <body>
                <h1>Security Analysis Report</h1>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Scan Results</h5>
                        <pre>{data.get('output', 'No output available')}</pre>
                    </div>
                </div>
            </body>
            </html>
            """
            pdfkit.from_string(simple_html, output_file, options=options)
            logging.info(f"Simple PDF generated as fallback at {output_file}")

        return jsonify({'url': f'/download/{os.path.basename(output_file)}', 'path': output_file}), 200
    except Exception as e:
        app.logger.error('Error generating PDF', exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    # Check if the request has a path parameter
    path = request.args.get('path')

    if path and os.path.exists(path):
        # If a specific path is provided and exists, use it
        file_path = path
    else:
        # Otherwise, look in the current directory
        file_path = os.path.join(os.getcwd(), filename)

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name=filename)
    else:
        logging.error(f"File not found at path: {file_path}")
        return jsonify({'error': 'File not found'}), 404

def get_repositories_from_github(tags):
    github_token = os.getenv('GITHUB_TOKEN')
    if not github_token:
        raise Exception("GitHub token not found. Please set the GITHUB_TOKEN environment variable.")

    headers = {
        'Authorization': f'token {github_token}'
    }
    search_url = f'https://api.github.com/search/repositories?q={tags}'
    response = requests.get(search_url, headers=headers, timeout=10)

    if response.status_code != 200:
        raise Exception(f"GitHub API error: {response.status_code}")

    repositories = response.json().get('items', [])
    logging.debug(f"GitHub API response for tags '{tags}': {repositories}")
    return repositories

@app.route('/security_posture/<repo_name>')
def security_posture(repo_name):
    """Display security posture score and recommendations for a repository"""
    # Get the latest security posture score
    posture_score = SecurityPostureScore.query.filter_by(repo_name=repo_name).order_by(
        SecurityPostureScore.scan_date.desc()).first()

    if not posture_score:
        flash(f"No security posture score found for repository {repo_name}", "warning")
        return redirect(url_for('dashboard_repository', repo_name=repo_name))

    # Get taint analysis results
    taint_results = TaintAnalysisResult.query.filter_by(repo_name=repo_name).order_by(
        TaintAnalysisResult.scan_date.desc()).first()

    # Parse recommendations from JSON
    recommendations = json.loads(posture_score.recommendations) if posture_score.recommendations else []

    # Parse taint analysis details from JSON
    taint_paths = json.loads(taint_results.detailed_results) if taint_results and taint_results.detailed_results else {}

    # Get historical scores for trend chart
    historical_scores = SecurityPostureScore.query.filter_by(repo_name=repo_name).order_by(
        SecurityPostureScore.scan_date).all()

    dates = [score.scan_date.strftime('%Y-%m-%d') for score in historical_scores]
    overall_scores = [score.overall_score for score in historical_scores]
    vulnerability_scores = [score.vulnerability_score for score in historical_scores]
    code_quality_scores = [score.code_quality_score for score in historical_scores]
    security_practices_scores = [score.security_practices_score for score in historical_scores]

    return render_template(
        'security_posture.html',
        repo_name=repo_name,
        posture_score=posture_score,
        taint_results=taint_results,
        recommendations=recommendations,
        taint_paths=taint_paths,
        dates=dates,
        overall_scores=overall_scores,
        vulnerability_scores=vulnerability_scores,
        code_quality_scores=code_quality_scores,
        security_practices_scores=security_practices_scores
    )

@app.route('/taint_analysis/<repo_name>')
def taint_analysis(repo_name):
    """Display detailed taint analysis results for a repository"""
    # Get the latest taint analysis results
    taint_results = TaintAnalysisResult.query.filter_by(repo_name=repo_name).order_by(
        TaintAnalysisResult.scan_date.desc()).first()

    if not taint_results:
        flash(f"No taint analysis results found for repository {repo_name}", "warning")
        return redirect(url_for('dashboard_repository', repo_name=repo_name))

    # Parse taint analysis details from JSON
    taint_paths = json.loads(taint_results.detailed_results) if taint_results.detailed_results else {}

    return render_template(
        'taint_analysis.html',
        repo_name=repo_name,
        taint_results=taint_results,
        taint_paths=taint_paths
    )

@app.route('/view_results')
def view_results():
    # Query all tool results from the database
    tool_results = ToolResult.query.all()
    results = []

    # Process the results
    for result in tool_results:
        results.append({
            'repo_name': result.repo_name,
            'tool_name': result.tool_name,
            'result': result.result,
            'timestamp': result.timestamp
        })

    # Render the results in a template
    return render_template('view_results.html', results=results)

def format_iso_date(iso_str):
    """Convert ISO 8601 date string to a more readable format."""
    try:
        return datetime.fromisoformat(iso_str.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return iso_str  # Return the original string if parsing fails

@app.route('/trigger_ci')
def trigger_ci():
    repo_url = request.args.get('repo_url', 'https://github.com/example/repo')  # Default repo URL
    ci_tool = request.args.get('ci_tool', 'jenkins')  # Default to Jenkins
    try:
        trigger_ci_pipeline(ci_tool, repo_url)
        flash(f"CI pipeline triggered successfully for {repo_url} using {ci_tool}.", "success")
    except Exception as e:
        logging.error(f"Failed to trigger CI pipeline: {e}")
        flash(f"Failed to trigger CI pipeline: {e}", "danger")
    return redirect(url_for('index'))

def get_detailed_info(repo_url):
    """Fetch detailed information about a GitHub repository with robust error handling."""
    if os.path.isdir(repo_url):  # Treat as a local path if it's a directory
        return get_local_repo_info(repo_url)

    github_token = os.getenv('GITHUB_TOKEN')
    headers = {'Authorization': f'token {github_token}'}
    api_url = repo_url.replace('https://github.com/', 'https://api.github.com/repos/')

    response = requests.get(api_url, headers=headers, timeout=10)
    if response.status_code == 200:
        repo_details = response.json()

        # Safe access to dictionary keys with default values if key is not present
        name = repo_details.get('name', 'Unknown Repository')
        updated_at = repo_details.get('updated_at', 'Unknown Date')
        updated_at = format_iso_date(updated_at) if updated_at != 'Unknown Date' else updated_at

        issues_response = requests.get(f"{api_url}/issues?state=open", headers=headers, timeout=10)
        pulls_response = requests.get(f"{api_url}/pulls", headers=headers, timeout=10)

        issues_count = len(issues_response.json()) if issues_response.status_code == 200 else 'Unknown'
        pulls_count = len(pulls_response.json()) if pulls_response.status_code == 200 else 'Unknown'

        detailed_info = {
            'html_url': repo_url,
            'name': name,
            'issues_count': issues_count,
            'pulls_count': pulls_count,
            'last_updated': updated_at,
            'stars': repo_details.get('stargazers_count', 0),
            'forks': repo_details.get('forks_count', 0),
            'watchers': repo_details.get('watchers_count', 0),
            'language': repo_details.get('language', 'Unknown')
        }
        logging.debug(f"Detailed information for repository '{repo_url}': {detailed_info}")
        return detailed_info
    else:
        error_info = {
            'html_url': repo_url,
            'error': f"Failed to fetch repo details, status code: {response.status_code}"
        }
        logging.error(f"Error fetching detailed information for repository '{repo_url}': {error_info}")
        return error_info

@app.route('/visualize', methods=['GET'])
def visualize():
    """Display the visualization page with a list of available repositories."""
    # Get a list of repositories that can be visualized
    repositories = []

    # Check the Untested directory for repositories
    untested_dir = 'Untested'
    if os.path.isdir(untested_dir):
        for item in os.listdir(untested_dir):
            repo_path = os.path.join(untested_dir, item)
            if os.path.isdir(repo_path):
                repositories.append({
                    'name': item,
                    'path': repo_path
                })

    # Check if a specific directory was provided in the query parameters
    custom_path = request.args.get('path')
    if custom_path and os.path.isdir(custom_path):
        # If the path is not already in the list, add it
        path_exists = any(repo['path'] == custom_path for repo in repositories)
        if not path_exists:
            repositories.append({
                'name': os.path.basename(custom_path),
                'path': custom_path
            })

    return render_template('visualize.html', repositories=repositories, diagram=None, repo_name=None)

@app.route('/visualize/<path:repo_path>', methods=['GET'])
def visualize_repository(repo_path):
    """Generate and display a visualization for a specific repository or directory."""
    try:
        # Check if the path exists
        if not os.path.exists(repo_path):
            # Try to resolve the path relative to the current directory
            absolute_path = os.path.abspath(repo_path)
            if not os.path.exists(absolute_path):
                # Try to resolve the path relative to the Untested directory
                untested_path = os.path.join('Untested', repo_path)
                if os.path.exists(untested_path):
                    repo_path = untested_path
                else:
                    return render_template('error.html',
                                          message=f"Path not found: {repo_path}",
                                          back_url=url_for('visualize'))

        # Get repository structure
        repo_data = get_repo_structure(repo_path)

        if 'error' in repo_data:
            return render_template('error.html',
                                  message=f"Error analyzing directory: {repo_data['error']}",
                                  back_url=url_for('visualize'))

        # Generate Mermaid diagram
        diagram_data = generate_mermaid_diagram(repo_data)

        if 'error' in diagram_data:
            return render_template('error.html',
                                  message=f"Error generating diagram: {diagram_data['error']}",
                                  back_url=url_for('visualize'))

        return render_template('visualize.html',
                               diagram=diagram_data['diagram'],
                               repo_name=diagram_data['repo_name'],
                               repo_path=diagram_data['repo_path'])
    except Exception as e:
        logging.error(f"Error visualizing directory: {str(e)}", exc_info=True)
        return render_template('error.html',
                              message=f"An error occurred while visualizing the directory: {str(e)}",
                              back_url=url_for('visualize'))

@app.route('/get_full_path', methods=['GET'])
def get_full_path():
    """Get the full path of a directory selected by the user."""
    dir_name = request.args.get('dir_name')
    if not dir_name:
        return jsonify({'error': 'No directory name provided'}), 400

    try:
        # First, check if the directory exists in the current working directory
        current_dir = os.getcwd()
        potential_path = os.path.join(current_dir, dir_name)

        if os.path.isdir(potential_path):
            return jsonify({'full_path': potential_path})

        # Next, check if it exists in the Untested directory
        untested_path = os.path.join(current_dir, 'Untested', dir_name)
        if os.path.isdir(untested_path):
            return jsonify({'full_path': untested_path})

        # Check common locations based on the operating system
        home_dir = os.path.expanduser('~')

        # Check BlueSpunge 2 4 directory in Downloads
        bluespunge_path = os.path.join(home_dir, 'Downloads', 'BlueSpunge 2 4', dir_name)
        if os.path.isdir(bluespunge_path):
            return jsonify({'full_path': bluespunge_path})

        # Check Downloads folder (common on all platforms)
        downloads_path = os.path.join(home_dir, 'Downloads', dir_name)
        if os.path.isdir(downloads_path):
            return jsonify({'full_path': downloads_path})

        # Check Documents folder (common on all platforms)
        documents_path = os.path.join(home_dir, 'Documents', dir_name)
        if os.path.isdir(documents_path):
            return jsonify({'full_path': documents_path})

        # Check Desktop folder (common on all platforms)
        desktop_path = os.path.join(home_dir, 'Desktop', dir_name)
        if os.path.isdir(desktop_path):
            return jsonify({'full_path': desktop_path})

        # If we can't find it, create it in the Untested directory
        try:
            untested_dir = os.path.join(os.getcwd(), 'Untested')
            os.makedirs(untested_dir, exist_ok=True)  # Make sure Untested exists

            new_dir_path = os.path.join(untested_dir, dir_name)
            # Don't create it yet, just return the path

            logging.info(f"Directory will be created at: {new_dir_path}")
            return jsonify({'full_path': new_dir_path, 'will_create': True})
        except Exception as create_error:
            logging.warning(f"Error preparing directory path: {str(create_error)}")
            # Just return the directory name as a fallback
            return jsonify({'full_path': dir_name})
    except Exception as e:
        logging.error(f"Error getting full path: {str(e)}", exc_info=True)
        # Return the directory name as a fallback
        return jsonify({'full_path': dir_name})

@app.route('/get_directory_contents', methods=['GET'])
def get_directory_contents():
    """Get the contents of a directory for the directory browser."""
    path = request.args.get('path', '')

    try:
        # If no path is provided, use the current working directory
        if not path:
            path = os.getcwd()

        # Check if the path exists and is a directory
        if not os.path.exists(path):
            return jsonify({'error': 'Path does not exist'}), 404

        if not os.path.isdir(path):
            return jsonify({'error': 'Path is not a directory'}), 400

        # Get the directory contents
        directories = []
        files = []

        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if os.path.isdir(item_path):
                directories.append(item)
            else:
                files.append(item)

        # Sort the lists alphabetically
        directories.sort()
        files.sort()

        return jsonify({
            'current_path': path,
            'directories': directories,
            'files': files
        })
    except Exception as e:
        logging.error(f"Error getting directory contents: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

# Dashboard routes
@app.route('/dashboard')
def dashboard_overview():
    """Display an overview of all repositories with metrics"""
    # Get the latest metrics for each repository
    latest_metrics = {}

    # Use a subquery to get the latest scan date for each repo
    subquery = db.session.query(
        MetricsHistory.repo_name,
        db.func.max(MetricsHistory.scan_date).label('max_date')
    ).group_by(MetricsHistory.repo_name).subquery()

    # Join with the main table to get the full records
    metrics_query = db.session.query(MetricsHistory).join(
        subquery,
        db.and_(
            MetricsHistory.repo_name == subquery.c.repo_name,
            MetricsHistory.scan_date == subquery.c.max_date
        )
    ).all()

    # Convert MetricsHistory objects to dictionaries for JSON serialization
    serializable_metrics = {}
    for metric in metrics_query:
        # Create a dictionary with all the metrics
        metric_dict = {
            'repo_name': metric.repo_name,
            'scan_date': metric.scan_date,
            'high_severity_issues': metric.high_severity_issues,
            'medium_severity_issues': metric.medium_severity_issues,
            'low_severity_issues': metric.low_severity_issues,
            'total_issues': metric.total_issues,
            'code_complexity': metric.code_complexity,
            'code_duplication': metric.code_duplication,
            'maintainability_index': metric.maintainability_index,
            'dependencies_with_vulnerabilities': metric.dependencies_with_vulnerabilities,
            'lines_of_code': metric.lines_of_code,
            'test_coverage': metric.test_coverage
        }
        latest_metrics[metric.repo_name] = metric
        serializable_metrics[metric.repo_name] = metric_dict

    return render_template(
        'dashboard_overview.html',
        metrics=serializable_metrics,
        metrics_objects=latest_metrics,  # Original objects for template use
        repositories=list(latest_metrics.keys())
    )

@app.route('/dashboard/<repo_name>')
def dashboard_repository(repo_name):
    """Display detailed metrics for a specific repository"""
    # Get historical metrics for this repository
    metrics_history = MetricsHistory.query.filter_by(repo_name=repo_name).order_by(MetricsHistory.scan_date).all()

    if not metrics_history:
        flash(f"No metrics found for repository {repo_name}", "warning")
        return redirect(url_for('dashboard_overview'))

    # Prepare data for charts
    dates = [m.scan_date.strftime('%Y-%m-%d') for m in metrics_history]

    # Security metrics
    security_data = {
        'high': [m.high_severity_issues for m in metrics_history],
        'medium': [m.medium_severity_issues for m in metrics_history],
        'low': [m.low_severity_issues for m in metrics_history],
        'total': [m.total_issues for m in metrics_history]
    }

    # Code quality metrics
    quality_data = {
        'complexity': [m.code_complexity for m in metrics_history],
        'duplication': [m.code_duplication for m in metrics_history],
        'maintainability': [m.maintainability_index for m in metrics_history]
    }

    # Additional metrics
    additional_data = {
        'dependencies': [m.dependencies_with_vulnerabilities for m in metrics_history],
        'lines_of_code': [m.lines_of_code for m in metrics_history],
        'test_coverage': [m.test_coverage for m in metrics_history]
    }

    # Get the latest metrics
    latest_metrics = metrics_history[-1] if metrics_history else None

    return render_template(
        'dashboard_repository.html',
        repo_name=repo_name,
        dates=dates,
        security_data=security_data,
        quality_data=quality_data,
        additional_data=additional_data,
        latest_metrics=latest_metrics
    )

@app.route('/heatmap/<repo_name>')
def code_risk_heatmap(repo_name):
    """Display a heat map of code risks for a repository"""
    # Get the latest risk data for this repository
    # Get the latest scan date for this repository
    latest_scan = db.session.query(db.func.max(FileRisk.scan_date)).filter(FileRisk.repo_name == repo_name).scalar()

    if latest_scan:
        # Get all risk data for the latest scan
        risk_data = db.session.query(FileRisk).filter(
            FileRisk.repo_name == repo_name,
            FileRisk.scan_date == latest_scan
        ).all()
    else:
        risk_data = []

    if not risk_data:
        flash(f"No risk data found for repository {repo_name}", "warning")
        return redirect(url_for('dashboard_repository', repo_name=repo_name))

    # Prepare data for the heat map
    file_risks = {}
    for risk in risk_data:
        file_risks[risk.file_path] = {
            'total_risk': risk.total_risk,
            'security_risk': risk.security_risk,
            'complexity_risk': risk.complexity_risk,
            'churn_risk': risk.churn_risk,
            'issue_count': risk.issue_count,
            'cyclomatic_complexity': risk.cyclomatic_complexity,
            'cognitive_complexity': risk.cognitive_complexity,
            'lines_changed': risk.lines_changed_last_month
        }

    # Get repository path
    repo_path = os.path.join('Untested', repo_name)

    return render_template(
        'code_risk_heatmap.html',
        repo_name=repo_name,
        repo_path=repo_path,
        file_risks=file_risks
    )

# Add links to scan results page
@app.route('/scan_results/<repo_name>/dashboard')
def scan_to_dashboard(repo_name):
    """Redirect from scan results to dashboard"""
    return redirect(url_for('dashboard_repository', repo_name=repo_name))

@app.route('/scan_results/<repo_name>/heatmap')
def scan_to_heatmap(repo_name):
    """Redirect from scan results to heat map"""
    return redirect(url_for('code_risk_heatmap', repo_name=repo_name))

@app.route('/security_issues/<repo_name>')
def security_issues(repo_name):
    """Display detailed security issues for a repository"""
    # Get the latest scan results from the database
    latest_metrics = MetricsHistory.query.filter_by(repo_name=repo_name).order_by(
        MetricsHistory.scan_date.desc()).first()

    if not latest_metrics:
        flash(f"No metrics found for repository {repo_name}", "warning")
        return redirect(url_for('dashboard_overview'))

    # Get the tool results for this repository
    tool_results = ToolResult.query.filter_by(repo_name=repo_name).order_by(
        ToolResult.timestamp.desc()).all()

    # Parse the security issues from the tool results
    issues = []
    # Findings whose severity/relevance we can't read off the tool's own
    # output need a TypeSafe judgment instead of a keyword/prefix guess.
    pending_findings = []
    pending_issues = []

    for result in tool_results:
        if result.tool_name == 'bandit':
            # Gate 1B envelope (see utils/scanner_status.py): only a
            # FINDINGS row has anything to parse - PASS/UNAVAILABLE/ERROR
            # correctly contribute zero issues without attempting to parse
            # text that, for ERROR in particular, may not even be bandit's
            # usual output shape. A row written before Gate 1B (raw bandit
            # stdout text - bandit is invoked without -f json, so this was
            # never real bandit-JSON) falls back to the legacy text parse.
            envelope = scanner_status.parse_result(result.result)
            if envelope is not None:
                if envelope['_status'] != scanner_status.FINDINGS:
                    continue
                bandit_output = envelope['_output'] or ''
            else:
                bandit_output = result.result
            for line in bandit_output.split('\n'):
                if ': [' in line and '] ' in line:
                    try:
                        # Example format: "filename.py:123: [B123:severity] Issue description"
                        file_info, issue_info = line.split(': [', 1)
                        file_path, line_number = file_info.rsplit(':', 1) if ':' in file_info else (file_info, '')
                        issue_id, issue_text = issue_info.split('] ', 1)

                        issue = {
                            'title': f"Security Issue {issue_id}",
                            'severity': None,  # filled in by triage_findings below
                            'description': issue_text,
                            'file_path': file_path,
                            'line_number': line_number,
                            'code_snippet': '',
                            'recommendation': 'Fix the security issue according to best practices.'
                        }
                        issues.append(issue)
                        pending_findings.append({
                            'tool': 'bandit',
                            'issue_id': issue_id,
                            'message': issue_text,
                            'file_path': file_path,
                        })
                        pending_issues.append(issue)
                    except Exception as e:
                        logging.error(f"Error parsing Bandit output line: {str(e)}")

        elif result.tool_name == 'pylint':
            # Same Gate 1B envelope handling as Bandit above.
            envelope = scanner_status.parse_result(result.result)
            if envelope is not None:
                if envelope['_status'] != scanner_status.FINDINGS:
                    continue
                pylint_output = envelope['_output'] or ''
            else:
                pylint_output = result.result
            for line in pylint_output.split('\n'):
                if ':' in line and '[' in line and ']' in line:
                    try:
                        # Example format: "filename.py:123:0: [C0111] Missing docstring"
                        parts = line.split(':', 3)
                        if len(parts) >= 4:
                            file_path = parts[0]
                            line_number = parts[1]
                            message = parts[3].strip()

                            # Extract issue ID and message
                            if '[' in message and ']' in message:
                                issue_id = message[message.find('[')+1:message.find(']')]
                                issue_text = message[message.find(']')+1:].strip()

                                issue = {
                                    'title': f"Code Issue {issue_id}",
                                    'severity': None,  # filled in by triage_findings below
                                    'description': issue_text,
                                    'file_path': file_path,
                                    'line_number': line_number,
                                    'code_snippet': '',
                                    'recommendation': 'Fix the code issue according to Python best practices.'
                                }
                                issues.append(issue)
                                pending_findings.append({
                                    'tool': 'pylint',
                                    'issue_id': issue_id,
                                    'message': issue_text,
                                    'file_path': file_path,
                                })
                                pending_issues.append(issue)
                    except Exception as e:
                        logging.error(f"Error parsing Pylint output line: {str(e)}")

        elif result.tool_name == 'osv-scanner':
            # OSV-Scanner findings are already normalized with a known
            # severity. Gate 1B envelope: _findings is the list to use, and
            # is only meaningful for PASS/FINDINGS (empty either way for
            # PASS) - UNAVAILABLE/ERROR rows correctly contribute nothing.
            # A pre-Gate-1B row stored the findings list directly as
            # result.result with no envelope around it.
            envelope = scanner_status.parse_result(result.result)
            if envelope is not None:
                if envelope['_status'] not in (scanner_status.PASS, scanner_status.FINDINGS):
                    continue
                osv_findings = envelope['_findings'] or []
            else:
                try:
                    osv_findings = json.loads(result.result)
                except json.JSONDecodeError as e:
                    logging.error(f"Error parsing OSV-Scanner results: {str(e)}")
                    continue
                if not isinstance(osv_findings, list):
                    continue
            try:
                for finding in osv_findings:
                    aliases = f" (aka {', '.join(finding['aliases'])})" if finding.get('aliases') else ''
                    issues.append({
                        'title': f"{finding['id']} in {finding['package']}@{finding['version']}{aliases}",
                        'severity': finding['severity'],
                        'description': finding['summary'],
                        'file_path': finding['file_path'],
                        'line_number': '',
                        'code_snippet': f"{finding['ecosystem']}:{finding['package']}@{finding['version']}",
                        'recommendation': f"Upgrade {finding['package']} to a version that resolves {finding['id']}."
                    })
            except KeyError as e:
                logging.error(f"Error parsing OSV-Scanner results: {str(e)}")

        elif result.tool_name == 'license-check':
            # License findings are already normalized with a known severity.
            # Same envelope/legacy handling as OSV-Scanner above.
            envelope = scanner_status.parse_result(result.result)
            if envelope is not None:
                if envelope['_status'] not in (scanner_status.PASS, scanner_status.FINDINGS):
                    continue
                license_findings = envelope['_findings'] or []
            else:
                try:
                    license_findings = json.loads(result.result)
                except json.JSONDecodeError as e:
                    logging.error(f"Error parsing license check results: {str(e)}")
                    continue
                if not isinstance(license_findings, list):
                    continue
            issues.extend(license_findings)

    # Replace the old keyword/prefix severity guessing with a calibrated
    # TypeSafe judgment, and drop Pylint findings that aren't actually
    # security-relevant instead of keyword-matching "security"/"vuln".
    triage_results = triage_findings(pending_findings)
    findings_to_drop = set()
    for issue, finding, (severity, is_security_relevant, _confidence) in zip(
        pending_issues, pending_findings, triage_results
    ):
        issue['severity'] = severity
        if finding['tool'] == 'pylint' and not is_security_relevant:
            findings_to_drop.add(id(issue))
    issues = [issue for issue in issues if id(issue) not in findings_to_drop]

    # Count issues by severity
    high_severity_count = sum(1 for issue in issues if issue['severity'] == 'High')
    medium_severity_count = sum(1 for issue in issues if issue['severity'] == 'Medium')
    low_severity_count = sum(1 for issue in issues if issue['severity'] == 'Low')

    return render_template(
        'security_issues.html',
        repo_name=repo_name,
        issues=issues,
        high_severity_count=high_severity_count,
        medium_severity_count=medium_severity_count,
        low_severity_count=low_severity_count
    )

@app.route('/binary-analysis', methods=['GET'])
def binary_analysis():
    """
    Display the binary analysis page with available tools.
    """
    analysis_tools = get_binary_analysis_tools()
    return render_template('binary_analysis.html', analysis_tools=analysis_tools)

@app.route('/binary-data/<path:file_path>', methods=['GET'])
def get_binary_data(file_path):
    """
    Serve binary data in chunks for the hex viewer.

    Args:
        file_path: Path to the binary file (URL encoded)

    Query Parameters:
        offset: Starting byte offset (default: 0)
        length: Number of bytes to return (default: 1024)

    Returns:
        JSON with binary data in hex format
    """
    try:
        # Decode the file path
        file_path = urllib.parse.unquote(file_path)

        # Log the original file path for debugging
        logging.info(f"Original file path: {file_path}")

        # First, try to find the file directly (for simple filenames)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            # File exists at the exact path provided
            pass
        else:
            # Try different path combinations
            cwd = os.getcwd()
            possible_paths = [
                file_path,                                  # As provided
                os.path.join(cwd, file_path),               # Relative to CWD
                os.path.join(cwd, os.path.basename(file_path)),  # Just the filename in CWD
                file_path.replace(cwd + '/' + cwd, cwd),    # Fix duplicate CWD
                file_path.replace(cwd + cwd, cwd),          # Fix duplicate CWD without slash
            ]

            # If path starts with ./, also try without it
            if file_path.startswith('./'):
                possible_paths.append(os.path.join(cwd, file_path[2:]))

            # Try each possible path
            for test_path in possible_paths:
                if os.path.exists(test_path) and os.path.isfile(test_path):
                    file_path = test_path
                    logging.info(f"Found file at: {file_path}")
                    break

        # Log the resolved file path for debugging
        logging.info(f"Resolved file path: {file_path}")

        # Get query parameters
        offset = request.args.get('offset', 0, type=int)
        length = request.args.get('length', 1024, type=int)

        # Limit maximum length to prevent large requests
        max_length = 4096
        if length > max_length:
            length = max_length

        # Check if file exists and is readable
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return jsonify({'error': f'File not found: {file_path}'}), 404

        if not os.path.isfile(file_path):
            return jsonify({'error': 'Not a file'}), 400

        if not os.access(file_path, os.R_OK):
            return jsonify({'error': 'File not readable'}), 403

        # Get file size
        file_size = os.path.getsize(file_path)

        # Validate offset
        if offset < 0 or offset >= file_size:
            return jsonify({'error': 'Invalid offset'}), 400

        # Read binary data
        with open(file_path, 'rb') as f:
            f.seek(offset)
            data = f.read(length)

        # Convert binary data to hex
        hex_data = data.hex(' ')

        # Create ASCII representation
        ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)

        return jsonify({
            'offset': offset,
            'length': len(data),
            'total_size': file_size,
            'hex_data': hex_data,
            'ascii_data': ascii_data
        })

    except Exception as e:
        logging.error(f"Error serving binary data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/generate-binary-report', methods=['POST'])
def generate_binary_report():
    """
    Generate a report for binary analysis results.

    Accepts JSON data with report configuration and returns a URL to download the report.
    """
    try:
        data = request.get_json()
        if not data or 'report_data' not in data:
            return jsonify({'success': False, 'error': 'No report data provided'}), 400

        report_data = data['report_data']
        report_format = 'pdf' if report_data.get('sections', {}).get('format', 'pdf') == 'pdf' else 'html'

        # Create a temporary directory for the report
        temp_dir = tempfile.mkdtemp()

        if report_format == 'pdf':
            output_file = os.path.join(temp_dir, 'Binary_Analysis_Report.pdf')
            report_url = f"/download/Binary_Analysis_Report.pdf?path={output_file}"
        else:
            output_file = os.path.join(temp_dir, 'Binary_Analysis_Report.html')
            report_url = f"/download/Binary_Analysis_Report.html?path={output_file}"

        # Generate HTML content for the report
        html_content = generate_binary_report_html(report_data)

        if report_format == 'pdf':
            # Configure pdfkit options
            options = {
                'enable-local-file-access': '',
                'no-stop-slow-scripts': '',
                'debug-javascript': '',
                'quiet': '',
                'margin-top': '10mm',
                'margin-right': '10mm',
                'margin-bottom': '10mm',
                'margin-left': '10mm',
                'encoding': 'UTF-8',
                'page-size': 'A4',
            }

            try:
                # Generate PDF from HTML
                pdfkit.from_string(html_content, output_file, options=options)
                logging.info(f"Binary analysis PDF report generated at {output_file}")
            except Exception as e:
                logging.error(f"Error generating PDF report: {str(e)}")
                return jsonify({'success': False, 'error': f"Error generating PDF: {str(e)}"}), 500
        else:
            # Save HTML report
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logging.info(f"Binary analysis HTML report generated at {output_file}")

        return jsonify({
            'success': True,
            'report_url': report_url
        })

    except Exception as e:
        logging.error(f"Error generating binary report: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

def generate_binary_report_html(report_data):
    """
    Generate HTML content for binary analysis report.

    Args:
        report_data: Dictionary containing report configuration and binary analysis data

    Returns:
        HTML string for the report
    """
    title = report_data.get('title', 'Binary Analysis Report')
    notes = report_data.get('notes', '')
    sections = report_data.get('sections', {})
    binary_path = report_data.get('binaryPath', '')
    analysis_result = report_data.get('analysisResult', {})

    # Start building HTML
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }}
            h1, h2, h3, h4 {{
                color: #2c3e50;
                margin-top: 1.5em;
            }}
            h1 {{
                border-bottom: 2px solid #3498db;
                padding-bottom: 10px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            .section {{
                margin-bottom: 30px;
                border: 1px solid #eee;
                border-radius: 5px;
                padding: 15px;
            }}
            .section-header {{
                background-color: #f8f9fa;
                padding: 10px;
                margin: -15px -15px 15px -15px;
                border-bottom: 1px solid #eee;
                border-radius: 5px 5px 0 0;
            }}
            .hex-dump {{
                font-family: monospace;
                white-space: pre;
                overflow-x: auto;
                font-size: 14px;
            }}
            .footer {{
                margin-top: 50px;
                border-top: 1px solid #eee;
                padding-top: 20px;
                font-size: 12px;
                color: #777;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <h1>{title}</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Binary File:</strong> {binary_path}</p>
    """

    # Add notes if provided
    if notes:
        html += f"""
        <div class="section">
            <div class="section-header">
                <h2>Notes</h2>
            </div>
            <p>{notes}</p>
        </div>
        """

    # Add summary section
    if sections.get('summary', False):
        html += """
        <div class="section">
            <div class="section-header">
                <h2>Summary</h2>
            </div>
            <p>This report contains the results of binary analysis performed on the specified file.</p>
        """

        # Add summary table with key metrics
        html += """
            <table>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
        """

        # File size
        file_info = analysis_result.get('fileInfo', {})
        if file_info:
            file_size = file_info.get('size', 'Unknown')
            file_type = file_info.get('type', 'Unknown')
            html += f"""
                <tr>
                    <td>File Size</td>
                    <td>{file_size} bytes</td>
                </tr>
                <tr>
                    <td>File Type</td>
                    <td>{file_type}</td>
                </tr>
            """

        # Number of sections
        sections_data = analysis_result.get('sections', [])
        if sections_data:
            html += f"""
                <tr>
                    <td>Number of Sections</td>
                    <td>{len(sections_data)}</td>
                </tr>
            """

        # Number of strings
        strings_data = analysis_result.get('strings', [])
        if strings_data:
            html += f"""
                <tr>
                    <td>Number of Strings</td>
                    <td>{len(strings_data)}</td>
                </tr>
            """

        # Number of functions
        functions_data = analysis_result.get('functions', [])
        if functions_data:
            html += f"""
                <tr>
                    <td>Number of Functions</td>
                    <td>{len(functions_data)}</td>
                </tr>
            """

        html += """
            </table>
        </div>
        """

    # Add file information section
    if sections.get('fileInfo', False) and analysis_result.get('fileInfo'):
        file_info = analysis_result.get('fileInfo', {})
        html += """
        <div class="section">
            <div class="section-header">
                <h2>File Information</h2>
            </div>
            <table>
                <tr>
                    <th>Property</th>
                    <th>Value</th>
                </tr>
        """

        for key, value in file_info.items():
            html += f"""
                <tr>
                    <td>{key}</td>
                    <td>{value}</td>
                </tr>
            """

        html += """
            </table>
        </div>
        """

    # Add headers section
    if sections.get('headers', False) and analysis_result.get('headers'):
        headers = analysis_result.get('headers', {})
        html += """
        <div class="section">
            <div class="section-header">
                <h2>Headers</h2>
            </div>
        """

        for header_type, header_data in headers.items():
            html += f"""
            <h3>{header_type}</h3>
            <table>
                <tr>
                    <th>Property</th>
                    <th>Value</th>
                </tr>
            """

            if isinstance(header_data, dict):
                for key, value in header_data.items():
                    html += f"""
                    <tr>
                        <td>{key}</td>
                        <td>{value}</td>
                    </tr>
                    """
            else:
                html += f"""
                <tr>
                    <td>Data</td>
                    <td>{header_data}</td>
                </tr>
                """

            html += """
            </table>
            """

        html += """
        </div>
        """

    # Add sections section
    if sections.get('sections', False) and analysis_result.get('sections'):
        sections_data = analysis_result.get('sections', [])
        html += """
        <div class="section">
            <div class="section-header">
                <h2>Sections</h2>
            </div>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Virtual Address</th>
                    <th>Size</th>
                    <th>Permissions</th>
                </tr>
        """

        for section in sections_data:
            name = section.get('name', 'Unknown')
            vaddr = section.get('vaddr', 0)
            size = section.get('size', 0)
            perms = section.get('permissions', '')

            html += f"""
                <tr>
                    <td>{name}</td>
                    <td>0x{vaddr:x}</td>
                    <td>{size} bytes</td>
                    <td>{perms}</td>
                </tr>
            """

        html += """
            </table>
        </div>
        """

    # Add strings section
    if sections.get('strings', False) and analysis_result.get('strings'):
        strings_data = analysis_result.get('strings', [])
        html += """
        <div class="section">
            <div class="section-header">
                <h2>Strings</h2>
            </div>
            <table>
                <tr>
                    <th>String</th>
                    <th>Address</th>
                </tr>
        """

        # Limit to first 100 strings to avoid huge reports
        for string_entry in strings_data[:100]:
            if isinstance(string_entry, dict):
                string_value = string_entry.get('string', '')
                string_addr = string_entry.get('address', 0)
                html += f"""
                    <tr>
                        <td>{string_value}</td>
                        <td>0x{string_addr:x}</td>
                    </tr>
                """
            else:
                html += f"""
                    <tr>
                        <td>{string_entry}</td>
                        <td>Unknown</td>
                    </tr>
                """

        if len(strings_data) > 100:
            html += f"""
                <tr>
                    <td colspan="2">... and {len(strings_data) - 100} more strings</td>
                </tr>
            """

        html += """
            </table>
        </div>
        """

    # Add functions section
    if sections.get('functions', False) and analysis_result.get('functions'):
        functions_data = analysis_result.get('functions', [])
        html += """
        <div class="section">
            <div class="section-header">
                <h2>Functions</h2>
            </div>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Address</th>
                    <th>Size</th>
                </tr>
        """

        for function in functions_data:
            name = function.get('name', 'Unknown')
            addr = function.get('address', 0)
            size = function.get('size', 0)

            html += f"""
                <tr>
                    <td>{name}</td>
                    <td>0x{addr:x}</td>
                    <td>{size} bytes</td>
                </tr>
            """

        html += """
            </table>
        </div>
        """

    # Add disassembly section
    if sections.get('disassembly', False) and analysis_result.get('disassembly'):
        disassembly = analysis_result.get('disassembly', {})
        html += """
        <div class="section">
            <div class="section-header">
                <h2>Disassembly</h2>
            </div>
        """

        for section_name, instructions in disassembly.items():
            html += f"""
            <h3>Section: {section_name}</h3>
            <table>
                <tr>
                    <th>Address</th>
                    <th>Bytes</th>
                    <th>Instruction</th>
                    <th>Operands</th>
                </tr>
            """

            # Limit to first 50 instructions per section
            for instr in instructions[:50]:
                addr = instr.get('address', 0)
                size = instr.get('size', 0)
                mnemonic = instr.get('mnemonic', '')
                operands = instr.get('operands', '')

                html += f"""
                    <tr>
                        <td>0x{addr:x}</td>
                        <td>{size} bytes</td>
                        <td>{mnemonic}</td>
                        <td>{operands}</td>
                    </tr>
                """

            if len(instructions) > 50:
                html += f"""
                    <tr>
                        <td colspan="4">... and {len(instructions) - 50} more instructions</td>
                    </tr>
                """

            html += """
            </table>
            """

        html += """
        </div>
        """

    # Add hex dump section
    if sections.get('hexDump', False) and report_data.get('binaryData'):
        binary_data = report_data.get('binaryData', {})
        html += """
        <div class="section">
            <div class="section-header">
                <h2>Hex Dump</h2>
            </div>
            <div class="hex-dump">
        """

        # Generate hex dump
        hex_bytes = binary_data.get('hexBytes', [])
        ascii_data = binary_data.get('asciiData', '')
        offset = binary_data.get('offset', 0)
        bytes_per_row = 16

        for i in range(0, len(hex_bytes), bytes_per_row):
            # Offset
            row_offset = offset + i
            html += f"0x{row_offset:08x}  "

            # Hex values
            row_hex = hex_bytes[i:i+bytes_per_row]
            hex_values = ""

            for j, byte in enumerate(row_hex):
                hex_values += f"{byte} "
                if j == 7:
                    hex_values += " "

            # Pad if needed
            hex_values = hex_values.ljust(bytes_per_row * 3 + 1)
            html += hex_values

            # ASCII representation
            row_ascii = ascii_data[i:i+bytes_per_row]
            html += f" |{row_ascii}|"
            html += "<br>"

        html += """
            </div>
        </div>
        """

    # Add footer
    html += """
        <div class="footer">
            <p>Generated by CodeBlue Binary Analysis Tool</p>
        </div>
    </body>
    </html>
    """

    return html

@app.route('/analyze-binary', methods=['POST'])
def analyze_binary():
    """
    Handle binary file upload and analysis.
    """
    # Get form parameters
    analysis_tool = request.form.get('analysis_tool', 'angr')
    temp_dir = None

    try:
        # Check if a file path was provided
        binary_file_path = request.form.get('binary_file_path', '')
        if binary_file_path and os.path.exists(binary_file_path):
            # Use the provided file path
            file_path = binary_file_path
        else:
            # Check for file upload
            if 'binary_file' not in request.files:
                return render_template('binary_analysis_results.html', error="No file selected or valid path provided")

            binary_file = request.files['binary_file']

            if binary_file.filename == '':
                return render_template('binary_analysis_results.html', error="No file selected or valid path provided")

            # Create a temporary directory to store the uploaded file
            temp_dir = tempfile.mkdtemp(prefix="codeblue_binary_analysis_")

            # Save the uploaded file
            file_path = os.path.join(temp_dir, binary_file.filename)
            binary_file.save(file_path)

        # Analyze the binary based on the selected tool
        if analysis_tool == 'basic':
            # Use basic analysis tools
            from utils.binary_analyzer import analyze_binary_with_basic_tools
            result = analyze_binary_with_basic_tools(file_path)
        elif analysis_tool == 'angr':
            # Use Angr for advanced analysis
            result = analyze_binary_with_angr(file_path)
        elif analysis_tool == 'ghidra':
            # Use Ghidra for advanced analysis
            result = analyze_binary_with_ghidra(file_path)
        elif analysis_tool == 'radare2':
            # Use Radare2 for advanced analysis
            result = analyze_binary_with_radare2(file_path)
        elif analysis_tool == 'capstone':
            # Use Capstone for disassembly
            if CAPSTONE_AVAILABLE:
                result = analyze_binary_with_capstone(file_path)
            else:
                return render_template('binary_analysis_results.html',
                                      error="Capstone is not available. Please install it using the setup button.")
        else:
            return render_template('binary_analysis_results.html',
                                  error=f"Analysis tool '{analysis_tool}' is not yet implemented")

        # Make sure binary_path is included in the result
        if isinstance(result, dict) and 'binary_path' not in result:
            result['binary_path'] = file_path

        return render_template('binary_analysis_results.html', result=result)

    except Exception as e:
        logging.error(f"Error during binary analysis: {str(e)}", exc_info=True)
        return render_template('binary_analysis_results.html',
                              error=f"An error occurred during analysis: {str(e)}")

    finally:
        # Clean up the temporary directory if it exists
        if temp_dir:
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error(f"Error cleaning up temporary directory: {str(e)}")

@app.route('/browse-files', methods=['GET'])
def browse_files():
    """
    Browse files and directories for the binary analysis page.
    """
    try:
        # Get the current directory from the query parameter
        current_dir = request.args.get('dir', os.getcwd())

        # Ensure the path exists and is a directory
        if not os.path.exists(current_dir) or not os.path.isdir(current_dir):
            current_dir = os.getcwd()

        # Get the parent directory
        parent_dir = os.path.dirname(current_dir)

        # List files and directories in the current directory
        items = []
        for item in os.listdir(current_dir):
            item_path = os.path.join(current_dir, item)
            is_dir = os.path.isdir(item_path)

            # Check if the file is a binary
            is_binary = False
            if not is_dir:
                try:
                    file_output = subprocess.check_output(['file', item_path], universal_newlines=True)
                    is_binary = 'ELF' in file_output or 'PE32' in file_output or 'Mach-O' in file_output or '.so' in item or '.dll' in item
                except Exception as e:
                    logging.debug(f"Could not determine file type for {item_path}: {e}")

            items.append({
                'name': item,
                'path': item_path,
                'is_dir': is_dir,
                'is_binary': is_binary
            })

        # Sort items: directories first, then files
        items.sort(key=lambda x: (not x['is_dir'], x['name']))

        return jsonify({
            'current_dir': current_dir,
            'parent_dir': parent_dir,
            'items': items
        })

    except Exception as e:
        logging.error(f"Error browsing files: {str(e)}")
        return jsonify({
            'error': f"Error browsing files: {str(e)}"
        }), 500


@app.route('/setup-ghidra', methods=['POST'])
def setup_ghidra():
    """
    Set up Ghidra by downloading and installing it directly.
    """
    try:
        logging.info("Setting up Ghidra...")

        # Install required dependencies. Run as two plain argv commands
        # instead of a shell=True string so no shell ever parses these
        # arguments (there's no need for shell chaining here: if `update`
        # fails we still want `install` to report its own error).
        logging.info("Installing dependencies...")
        subprocess.run(
            ['apt-get', 'update'],
            capture_output=True,
            universal_newlines=True,
            timeout=600,
        )
        install_process = subprocess.run(
            ['apt-get', 'install', '-y', 'wget', 'unzip', 'openjdk-17-jdk'],
            capture_output=True,
            universal_newlines=True,
            timeout=600,
        )

        if install_process.returncode != 0:
            logging.error(f"Dependencies installation failed: {install_process.stderr}")
            return jsonify({
                'success': False,
                'message': f"Dependencies installation failed: {install_process.stderr}"
            })

        # Create directories
        ghidra_dir = '/opt/ghidra'
        if not os.path.exists(ghidra_dir):
            os.makedirs(ghidra_dir)

        # Download Ghidra
        ghidra_version = '10.3.2'
        ghidra_zip = f'/tmp/ghidra_{ghidra_version}_PUBLIC_20230711.zip'

        logging.info(f"Downloading Ghidra {ghidra_version}...")
        download_cmd = [
            'wget',
            '-q',
            f'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_{ghidra_version}_build/ghidra_{ghidra_version}_PUBLIC_20230711.zip',
            '-O',
            ghidra_zip
        ]

        download_process = subprocess.Popen(
            download_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        stdout, stderr = download_process.communicate(timeout=900)  # 15 minutes timeout

        if download_process.returncode != 0:
            logging.error(f"Ghidra download failed: {stderr}")
            return jsonify({
                'success': False,
                'message': f"Download failed: {stderr}"
            })

        # Clean up any existing extracted files
        logging.info("Cleaning up existing files...")
        for item in os.listdir('/tmp'):
            if item.startswith(f'ghidra_{ghidra_version}_PUBLIC'):
                try:
                    path = os.path.join('/tmp', item)
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                    logging.info(f"Removed {path}")
                except Exception as e:
                    logging.warning(f"Failed to remove {item}: {str(e)}")

        # Extract Ghidra (with -o to overwrite without prompting)
        logging.info("Extracting Ghidra...")
        extract_cmd = [
            'unzip',
            '-q',
            '-o',  # Overwrite files without prompting
            ghidra_zip,
            '-d',
            '/tmp'
        ]

        extract_process = subprocess.Popen(
            extract_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        stdout, stderr = extract_process.communicate(timeout=600)  # 10 minutes timeout

        if extract_process.returncode != 0:
            logging.error(f"Ghidra extraction failed: {stderr}")
            return jsonify({
                'success': False,
                'message': f"Extraction failed: {stderr}"
            })

        # Find the extracted directory
        logging.info("Installing Ghidra...")
        extracted_dir = None
        for item in os.listdir('/tmp'):
            if item.startswith(f'ghidra_{ghidra_version}_PUBLIC'):
                extracted_dir = os.path.join('/tmp', item)
                break

        if not extracted_dir:
            logging.error("Ghidra extraction failed: Could not find extracted directory")
            return jsonify({
                'success': False,
                'message': "Extraction failed: Could not find extracted directory"
            })

        logging.info(f"Found extracted directory: {extracted_dir}")

        # Copy files to the installation directory. shutil.copytree expands
        # the wildcard in Python instead of a shell, so extracted_dir (built
        # from a directory name found on disk) never reaches a shell string.
        shutil.copytree(extracted_dir, ghidra_dir, dirs_exist_ok=True)

        # Check if the move was successful
        if not os.path.exists(f'{ghidra_dir}/ghidraRun'):
            logging.error("Ghidra installation failed: ghidraRun not found")
            return jsonify({
                'success': False,
                'message': "Installation failed: ghidraRun not found. The move command may have failed."
            })

        # Make the Ghidra run script executable
        os.chmod(f'{ghidra_dir}/ghidraRun', 0o700)

        # Set environment variable
        os.environ['GHIDRA_PATH'] = ghidra_dir

        # Create a flag file to indicate Ghidra is installed
        with open('/tmp/ghidra_installed', 'w') as f:
            f.write('installed')

        logging.info("Ghidra setup completed successfully")

        # Restart the application to pick up the new environment
        def restart_app():
            time.sleep(2)  # Wait for the response to be sent
            logging.info("Restarting application...")
            os.execv(sys.executable, ['python'] + sys.argv)

        threading.Thread(target=restart_app).start()

        return jsonify({
            'success': True,
            'message': 'Ghidra setup completed successfully. The application will restart in a few seconds.'
        })

    except subprocess.TimeoutExpired:
        logging.error("Ghidra setup timed out")
        return jsonify({
            'success': False,
            'message': 'Setup timed out. Ghidra is a large download and may take a while to install. Please try again or check the server logs.'
        })

    except Exception as e:
        logging.error(f"Error setting up Ghidra: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        })

@app.route('/setup-radare2', methods=['POST'])
def setup_radare2():
    """
    Set up Radare2 by installing it directly.
    """
    try:
        logging.info("Setting up Radare2...")

        # Install dependencies as two plain argv commands (see setup_ghidra
        # for why this replaced a shell=True string).
        logging.info("Installing dependencies...")
        subprocess.run(
            ['apt-get', 'update'],
            capture_output=True,
            universal_newlines=True,
            timeout=300,
        )
        subprocess.run(
            ['apt-get', 'install', '-y', 'git', 'make', 'gcc', 'g++',
             'pkg-config', 'libzip-dev', 'zlib1g-dev'],
            capture_output=True,
            universal_newlines=True,
            timeout=300,
        )

        # Clone Radare2 repository
        logging.info("Cloning Radare2 repository...")
        clone_cmd = [
            'git', 'clone', '--depth', '1',
            'https://github.com/radareorg/radare2.git',
            '/tmp/radare2'
        ]

        clone_process = subprocess.Popen(
            clone_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        stdout, stderr = clone_process.communicate(timeout=300)  # 5 minutes timeout

        if clone_process.returncode != 0:
            logging.error(f"Radare2 clone failed: {stderr}")
            return jsonify({
                'success': False,
                'message': f"Clone failed: {stderr}"
            })

        # Install Radare2. cwd replaces the `cd ... &&` shell chain.
        logging.info("Installing Radare2...")
        install_process = subprocess.run(
            ['./sys/install.sh'],
            cwd='/tmp/radare2',
            capture_output=True,
            universal_newlines=True,
            timeout=600,
        )

        if install_process.returncode != 0:
            logging.error(f"Radare2 installation failed: {install_process.stderr}")
            return jsonify({
                'success': False,
                'message': f"Installation failed: {install_process.stderr}"
            })

        # Set environment variable
        os.environ['RADARE2_AVAILABLE'] = 'true'

        # Create a flag file to indicate Radare2 is installed
        with open('/tmp/radare2_installed', 'w') as f:
            f.write('installed')

        logging.info("Radare2 setup completed successfully")

        # Restart the application to pick up the new environment
        def restart_app():
            time.sleep(2)  # Wait for the response to be sent
            logging.info("Restarting application...")
            os.execv(sys.executable, ['python'] + sys.argv)

        threading.Thread(target=restart_app).start()

        return jsonify({
            'success': True,
            'message': 'Radare2 setup completed successfully. The application will restart in a few seconds.'
        })

    except subprocess.TimeoutExpired:
        logging.error("Radare2 setup timed out")
        return jsonify({
            'success': False,
            'message': 'Setup timed out after 10 minutes'
        })

    except Exception as e:
        logging.error(f"Error setting up Radare2: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        })

@app.route('/setup-capstone', methods=['POST'])
def setup_capstone():
    """
    Set up Capstone by running the setup script and restarting the container.
    """
    try:
        # Check if the setup_capstone.sh script exists
        if not os.path.exists('install_capstone.sh'):
            return jsonify({
                'success': False,
                'message': 'Setup script not found. Please make sure install_capstone.sh exists in the project root.'
            })

        # Make the script executable
        os.chmod('install_capstone.sh', 0o700)

        # Run the setup script
        logging.info("Running Capstone setup script...")
        setup_process = subprocess.Popen(
            ['./install_capstone.sh'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        stdout, stderr = setup_process.communicate(timeout=600)  # 10 minutes timeout

        if setup_process.returncode != 0:
            logging.error(f"Capstone setup failed: {stderr}")
            return jsonify({
                'success': False,
                'message': f"Setup script failed: {stderr}"
            })

        logging.info("Capstone setup completed successfully")

        # Restart the container (this will terminate the current process)
        # We'll do this in a separate thread to allow the response to be sent
        def restart_container():
            time.sleep(2)  # Wait for the response to be sent
            logging.info("Restarting container...")
            subprocess.run(['docker-compose', 'down'], check=False)
            subprocess.run(['docker-compose', 'up', '-d'], check=False)

        threading.Thread(target=restart_container).start()

        return jsonify({
            'success': True,
            'message': 'Capstone setup completed successfully. The server will restart in a few seconds.'
        })

    except subprocess.TimeoutExpired:
        logging.error("Capstone setup timed out")
        return jsonify({
            'success': False,
            'message': 'Setup script timed out after 10 minutes'
        })

    except Exception as e:
        logging.error(f"Error setting up Capstone: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        })

# Register the CI integration blueprint
app.register_blueprint(ci_integration_app, url_prefix='/ci')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables for all models defined

    # Get host and port from configuration
    host = app.config.get('HOST', '0.0.0.0')
    port = app.config.get('PORT', 5001)
    debug = app.config.get('DEBUG', False)

    # Log the server startup information
    logging.info(f"Starting CodeBlue server on {host}:{port} (debug={debug})")
    logging.info(f"Application will be accessible at http://{host}:{port}")

    # Run the Flask application
    app.run(debug=debug, host=host, port=port)