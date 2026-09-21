#!/usr/bin/env just --justfile

# List available commands
default:
    @just --list

# Create virtualenv if it doesn't exist or is missing dependencies
venv:
    #!/usr/bin/env bash
    set -e -o pipefail
    if [ ! -d ".venv" ] || (! . .venv/bin/activate && pip freeze | grep -q "pytest"); then
        echo "Creating new virtualenv..."
        python -m venv .venv
        . .venv/bin/activate
        pip install --upgrade pip -r requirements-dev.txt -e .
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

# Update Go dependencies
update-go-dependencies:
    #!/usr/bin/env bash

    # Define the cooldown period in seconds (5 days)
    COOLDOWN_SEC=$((5 * 24 * 60 * 60))
    CURRENT_TIME=$(date +%s)

    # Get all direct dependencies that have an update available
    # We output in JSON format to get the Time field of the latest version
    pushd gotfparse
    echo "$PWD"
    echo "Checking for updates to direct dependencies..."
    go list -m -u -json all | jq -c 'select(.Update != null and .Indirect == false)' | while read -r mod; do
        echo "Processing module: $mod"
        MOD_PATH=$(echo "$mod" | jq -r '.Path')
        NEXT_VER=$(echo "$mod" | jq -r '.Update.Version')
        NEXT_TIME_STR=$(echo "$mod" | jq -r '.Update.Time')

        # Convert ISO8601 time to unix timestamp
        # Note: MacOS 'date' syntax may differ slightly from Linux/GNU
        NEXT_TIME=$(date -d "$NEXT_TIME_STR" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$NEXT_TIME_STR" +%s)

        AGE=$((CURRENT_TIME - NEXT_TIME))

        if [ "$AGE" -ge "$COOLDOWN_SEC" ]; then
            echo "Updating $MOD_PATH to $NEXT_VER (Age: $((AGE/86400)) days)"
            go get -v "$MOD_PATH@$NEXT_VER"
        else
            echo "Skipping $MOD_PATH ($NEXT_VER is only $((AGE/86400)) days old)"
        fi
    done

    echo "Tidying..."
    # Clean up go.mod and go.sum
    go mod tidy -v

    popd
    echo "Done"

# Update dev dependencies
update-dev-dependencies:
    uv --version || (echo "Please install uv, see: https://docs.astral.sh/uv/getting-started/installation/"; exit 1)
    uv tool run --from pip-tools pip-compile requirements-dev.in > requirements-dev.txt

# Show which trivy source the go module currently resolves to
show-trivy:
    @grep '^replace github.com/aquasecurity/trivy' gotfparse/go.mod

# Point trivy at a local checkout (clone or worktree) and rebuild
use-local-trivy path: venv
    #!/usr/bin/env bash
    set -euo pipefail
    # Use this to validate a fork change end to end before opening a PR.
    # The edit is local-only: a filesystem path must never be committed, so
    # restore it with `just use-pinned-trivy <ref>` when you are done.
    target="$(cd "{{ path }}" && pwd)"
    if [ ! -f "$target/go.mod" ]; then
        echo "error: no go.mod found in $target" >&2
        exit 1
    fi
    (cd gotfparse && go mod edit -replace github.com/aquasecurity/trivy="$target")
    . .venv/bin/activate && pip install -e . >/dev/null
    grep '^replace github.com/aquasecurity/trivy' gotfparse/go.mod

# Pin trivy to a gitref (branch, tag or SHA) on the cloud-custodian fork
use-pinned-trivy ref="main": venv
    #!/usr/bin/env bash
    set -euo pipefail
    # `go list -m` resolves the ref to a pseudo-version, so the base version
    # and commit timestamp are computed by go rather than assembled by hand.
    # The ref must exist on the fork remote -- upstream-only tags will not
    # resolve, since the fork does not carry them.
    fork=github.com/cloud-custodian/trivy
    cd gotfparse
    version="$(go list -m "$fork@{{ ref }}" | awk '{print $2}')"
    if [ -z "$version" ]; then
        echo "error: could not resolve {{ ref }} on $fork" >&2
        exit 1
    fi
    go mod edit -replace github.com/aquasecurity/trivy="$fork@$version"
    go mod tidy
    cd ..
    . .venv/bin/activate && pip install -e . >/dev/null
    grep '^replace github.com/aquasecurity/trivy' gotfparse/go.mod
