#!/usr/bin/env just --justfile

# List available commands
default:
    @just --list

# Create virtualenv if it doesn't exist or is missing dependencies
venv:
    #!/usr/bin/env bash
    if [ ! -d ".venv" ] || ! . .venv/bin/activate && pip freeze | grep -q "pytest"; then
        echo "Creating new virtualenv..."
        python -m venv .venv
        . .venv/bin/activate && python -m pip install --upgrade pip
        . .venv/bin/activate && pip install -r requirements-dev.txt
        . .venv/bin/activate && pip install -e .
    else
        echo "Using existing virtualenv..."
    fi

# Install development dependencies
install: venv
    . .venv/bin/activate && pip install -r requirements-dev.txt
    . .venv/bin/activate && pip install -e .

# Run black code formatter
fmt: venv
    . .venv/bin/activate && black tfparse tests

# Check code formatting with black
fmt-check: venv
    . .venv/bin/activate && black --check tfparse tests

# Run flake8 linter
lint: venv
    . .venv/bin/activate && flake8 --verbose tfparse tests

# Run all linting checks
check: fmt-check lint

# Run tests with pytest
test *args: venv
    . .venv/bin/activate && pytest {{args}}

# Run tests with coverage
test-cov: venv
    . .venv/bin/activate && pytest --cov=tfparse tests

# Run all checks (format, lint, test)
all: check test

# Clean up Python cache files and virtualenv
clean:
    find . -type d -name "__pycache__" -exec rm -r {} +
    find . -type f -name "*.pyc" -delete
    find . -type f -name "*.pyo" -delete
    find . -type f -name "*.pyd" -delete
    find . -type f -name ".coverage" -delete
    find . -type d -name "*.egg-info" -exec rm -r {} +
    find . -type d -name "*.egg" -exec rm -r {} +
    find . -type d -name ".pytest_cache" -exec rm -r {} +
    find . -type d -name ".coverage" -exec rm -r {} +
    find . -type d -name "htmlcov" -exec rm -r {} +
    rm -rf .venv

# Install Delve if not present
install-dlv:
    go install github.com/go-delve/delve/cmd/dlv@latest

# Debug Go code with Delve
debug cmd args: install-dlv
    cd gotfparse && dlv debug --check-go-version=false ./cmd/{{cmd}}/main.go -- ../{{args}} 