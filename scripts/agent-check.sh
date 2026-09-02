#!/usr/bin/env bash

# Read-only quality gate for an AI agent or CI job.
# Unlike `make fmt`, this script never rewrites source files.
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_dir="${GOCACHE_DIR:-${repo_dir}/.gocache}"
mkdir -p "${cache_dir}"
export GOCACHE="${cache_dir}"

cd "${repo_dir}"

echo "Checking Go formatting..."
format_files="$(gofmt -l $(rg --files -g '*.go'))"
if [[ -n "${format_files}" ]]; then
	printf 'Unformatted Go files:\n%s\n' "${format_files}"
	exit 1
fi

echo "Running go vet..."
go vet ./...

echo "Running golangci-lint..."
golangci-lint run ./...

echo "Running tests..."
go test ./...

echo "Agent checks passed."
