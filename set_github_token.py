# set_github_token.py
import requests

def validate_github_token(github_token):
    headers = {
        'Authorization': f'token {github_token}'
    }
    response = requests.get('https://api.github.com/user', headers=headers, timeout=10)
    return response.status_code == 200

def set_github_token():
    while True:
        github_token = input("Please enter your GitHub token: ")
        if validate_github_token(github_token):
            with open('.env', 'w') as f:
                f.write(f'GITHUB_TOKEN={github_token}')
            print("GitHub token saved to .env file.")
            break
        else:
            print("Invalid GitHub token. Please try again.")

if __name__ == "__main__":
    set_github_token()