@echo off
echo Installing Python static analysis tools...

REM Create a virtual environment if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate the virtual environment
call venv\Scripts\activate.bat

REM Install core dependencies
echo Installing core dependencies...
pip install -r requirements.txt

REM Install specific versions of tools if needed
echo Installing specific versions of tools...

REM Existing tools
pip install bandit==1.7.0
pip install pylint==2.11.1
pip install safety==1.10.3
pip install semgrep==0.72.0
pip install black==21.9b0
pip install flake8==3.9.2

REM New Python static analysis tools
echo Installing new Python static analysis tools...
pip install mypy==0.910
pip install pyright==0.0.13
pip install prospector==1.6.0
pip install pyre-check==0.9.10
pip install vulture==2.3
pip install radon==5.1.0

REM Install dlint (which is a flake8 plugin)
pip install dlint==0.12.0

REM Additional flake8 plugins
echo Installing additional flake8 plugins...
pip install flake8-django==1.1.2
pip install flake8-docstrings==1.6.0
pip install flake8-bugbear==21.9.2
pip install flake8-comprehensions==3.6.1
pip install flake8-return==1.1.3

echo Installation complete!
echo To activate the virtual environment, run: venv\Scripts\activate.bat
