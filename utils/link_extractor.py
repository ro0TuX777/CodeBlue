import requests
from datetime import datetime
import os
from git import Repo  # Importing the Repo class from GitPython

def get_repositories_from_github(tags):
    """Fetches repositories from GitHub based on specified tags."""
    github_token = os.getenv('GITHUB_TOKEN')
    headers = {'Authorization': f'token {github_token}'}
    url = f"https://api.github.com/search/repositories?q={tags}&sort=stars"
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200:
        return response.json()['items']
    else:
        raise Exception(f"GitHub API error: {response.status_code}")

def format_iso_date(iso_str):
    """Convert ISO 8601 date string to a more readable format."""
    try:
        return datetime.fromisoformat(iso_str.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return iso_str  # Return the original string if parsing fails

def get_detailed_info(repo_url):
    """Fetch detailed information about a GitHub repository with robust error handling."""
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

        return {
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
    else:
        return {
            'html_url': repo_url,
            'error': f"Failed to fetch repo details, status code: {response.status_code}"
        }

def clone_repository(repo_url, local_dir):
    """Clones a GitHub repository to a specified local directory."""
    try:
        Repo.clone_from(repo_url, local_dir)
        return f"Successfully cloned {repo_url} to {local_dir}"
    except Exception as e:
        return f"Failed to clone {repo_url}: {str(e)}"