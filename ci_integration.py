# ci_integration.py

from flask import Blueprint, request, jsonify
import logging
import subprocess

ci_integration_app = Blueprint('ci_integration_app', __name__)

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{e.cmd}' failed with return code {e.returncode}")
        logging.error(f"Output: {e.output}")
        return None

# Function to set up CI tools (example for Jenkins and GitLab CI)
def setup_ci_tools():
    logging.info("Setting up CI tools...")
    
    # Example command for setting up Jenkins
    jenkins_command = ["sudo", "apt-get", "install", "-y", "jenkins"]
    jenkins_output = run_command(jenkins_command)
    if jenkins_output:
        logging.info("Jenkins setup completed successfully.")
    
    # Example command for setting up GitLab CI runner
    gitlab_runner_command = ["sudo", "gitlab-runner", "install"]
    gitlab_runner_output = run_command(gitlab_runner_command)
    if gitlab_runner_output:
        logging.info("GitLab CI runner setup completed successfully.")

    # Add other CI tool setup commands as needed

# Function to trigger a CI pipeline
def trigger_ci_pipeline(ci_tool, repo_url, branch="main"):
    if ci_tool.lower() == "jenkins":
        jenkins_trigger_command = ["jenkins-cli", "build", repo_url, "--branch", branch]
        jenkins_output = run_command(jenkins_trigger_command)
        if jenkins_output:
            logging.info("Jenkins pipeline triggered successfully.")
            return "Jenkins pipeline triggered successfully."
    elif ci_tool.lower() == "gitlab":
        gitlab_trigger_command = ["gitlab-runner", "run", "--url", repo_url, "--executor", "shell"]
        gitlab_output = run_command(gitlab_trigger_command)
        if gitlab_output:
            logging.info("GitLab CI pipeline triggered successfully.")
            return "GitLab CI pipeline triggered successfully."
    else:
        logging.error(f"Unsupported CI tool: {ci_tool}")
        return f"Unsupported CI tool: {ci_tool}"

# Function to check the status of a CI pipeline
def check_ci_pipeline_status(ci_tool, pipeline_id):
    if ci_tool.lower() == "jenkins":
        jenkins_status_command = ["jenkins-cli", "console", pipeline_id]
        jenkins_status_output = run_command(jenkins_status_command)
        if jenkins_status_output:
            logging.info(f"Jenkins pipeline status: {jenkins_status_output}")
            return jenkins_status_output
    elif ci_tool.lower() == "gitlab":
        gitlab_status_command = ["gitlab-runner", "status", pipeline_id]
        gitlab_status_output = run_command(gitlab_status_command)
        if gitlab_status_output:
            logging.info(f"GitLab CI pipeline status: {gitlab_status_output}")
            return gitlab_status_output
    else:
        logging.error(f"Unsupported CI tool: {ci_tool}")
        return f"Unsupported CI tool: {ci_tool}"

@ci_integration_app.route('/trigger_ci', methods=['GET'])
def trigger_ci():
    repo_url = request.args.get('repo_url')
    ci_tool = request.args.get('ci_tool')
    if not repo_url or not ci_tool:
        return jsonify({'error': 'Missing repository URL or CI tool'}), 400

    if ci_tool.lower() == 'jenkins':
        command = ['jenkins-cli', 'build', repo_url]
    elif ci_tool.lower() == 'travis_ci':
        command = ['travis', 'trigger', repo_url]
    elif ci_tool.lower() == 'circleci':
        command = ['circleci', 'build', '--repo', repo_url]
    elif ci_tool.lower() == 'github_actions':
        command = ['gh', 'workflow', 'run', 'main.yml', '--repo', repo_url]
    else:
        return jsonify({'error': 'Unsupported CI tool'}), 400

    output = run_command(command)
    if output:
        return jsonify({'message': f'{ci_tool} pipeline triggered successfully.', 'output': output})
    else:
        return jsonify({'error': f'Failed to trigger {ci_tool} pipeline.'}), 500

@ci_integration_app.route('/check_ci_status', methods=['GET'])
def check_ci_status():
    ci_tool = request.args.get('ci_tool')
    pipeline_id = request.args.get('pipeline_id')
    if not ci_tool or not pipeline_id:
        return jsonify({'error': 'Missing required parameters'}), 400
    result = check_ci_pipeline_status(ci_tool, pipeline_id)
    return jsonify({'status': result})