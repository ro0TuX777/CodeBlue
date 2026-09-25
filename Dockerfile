FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    nodejs \
    npm \
    golang \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Skip Go tools installation as they're causing issues
# We'll use Python-based tools instead

# Install Node.js tools, pinned like the Go binaries below.
#
# eslint is pinned to the last 8.x release deliberately: ESLint 9+ requires
# the new "flat config" (eslint.config.*) format and refuses to run at all
# against a repository that only has the legacy .eslintrc.* format still
# common in real-world JS codebases (confirmed in a real build: unpinned
# `npm install -g eslint` resolved to 10.11.0, which failed outright -
# "ESLint couldn't find an eslint.config.* file" - against every fixture
# tested, clean or not, since run_eslint() in utils/external_scanners.py
# doesn't supply its own config and relies on the scanned repo's own).
RUN npm install -g eslint@8.57.1 jshint@2.13.6

# Install OSV-Scanner (multi-ecosystem dependency vulnerability scanner).
# Standalone Go binary, pinned by version like GitLeaks/TFSec below.
RUN curl -L https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_linux_amd64 \
    -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner

# Install GitLeaks (secret detection) and TFSec (Terraform security scan).
# Same pinned versions used in download_dependencies.sh's offline install path.
RUN curl -L https://github.com/zricethezav/gitleaks/releases/download/v8.8.12/gitleaks_8.8.12_linux_x64.tar.gz \
    -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz
RUN curl -L https://github.com/aquasecurity/tfsec/releases/download/v1.28.1/tfsec-linux-amd64 \
    -o /usr/local/bin/tfsec \
    && chmod +x /usr/local/bin/tfsec

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Capstone
RUN pip install --no-cache-dir capstone && \
    echo "export CAPSTONE_AVAILABLE=true" >> /etc/environment && \
    export CAPSTONE_AVAILABLE=true

# Additional Python tools not pinned in requirements.txt.
# bandit/pylint/safety/semgrep/black/flake8 are already installed at the
# versions pinned in requirements.txt above; installing them again here
# unpinned would silently override those pins.
#
# flake8-django is deliberately excluded: it requires astroid<3.0.0, which
# silently downgrades the astroid pylint==3.2.2 needs (astroid>=3.2.2) and
# breaks pylint outright (AttributeError: module 'astroid.nodes' has no
# attribute 'TypeAlias' on every invocation - confirmed in a real build).
# Nothing in CodeBlue's own orchestration invokes flake8-django; it isn't
# one of the scanners run_bluescrub() runs, so dropping it costs nothing.
RUN pip install --no-cache-dir \
    mypy \
    vulture \
    radon \
    flake8-docstrings \
    flake8-bugbear \
    flake8-comprehensions \
    flake8-return

# No additional tools needed

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p Untested
RUN mkdir -p saved_repositories

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 5001

# Run the application
CMD ["python", "app.py"]
