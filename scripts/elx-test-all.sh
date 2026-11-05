#!/usr/bin/env bash
# Full three-repository verification: run from WSL/Linux using sibling checkouts.
# Intended for disposable local test data, never a production DSN.
set -Eeuo pipefail

for go_bin_dir in /snap/bin /usr/local/go/bin; do
    if [[ -x "$go_bin_dir/go" && ":$PATH:" != *":$go_bin_dir:"* ]]; then
        export PATH="$go_bin_dir:$PATH"
    fi
done

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
core=$(cd -- "${ELXRAY_SOURCE:-$root/../ElXray}" && pwd)
panel=$(cd -- "${ELX_UI_SOURCE:-$root/../ElX-ui}" && pwd)
current="preflight"
on_error() {
    local exit_code=$?
    echo "FAIL: $current (exit $exit_code)" >&2
    exit "$exit_code"
}
trap on_error ERR
step() {
    current=$1
    shift
    printf '\n===== %s =====\n' "$current"
    "$@"
    printf 'PASS: %s\n' "$current"
}
for tool in go git openssl python3 gcc docker node npm make; do
    command -v "$tool" >/dev/null || {
        echo "MISSING: $tool; required for full three-repository checks" >&2
        exit 1
    }
done
if ! docker info >/dev/null 2>&1 && [[ -z "${ELX_CONTROL_POSTGRES_DSN:-}" ]]; then
    echo 'Docker Desktop unavailable; enable its WSL integration' >&2
    exit 1
fi
node_major=$(node -p 'Number(process.versions.node.split(".")[0])')
if (( node_major < 26 )); then
    echo "ElX-ui requires Node 26+, but current Node is $(node --version). Use nvm install 26 && nvm use 26 in WSL." >&2
    exit 1
fi
if ! command -v golangci-lint >/dev/null; then
    echo 'MISSING: golangci-lint; ElX-ui make verify requires it. Install the version supported by the panel go.mod.' >&2
    exit 1
fi
echo "Go: $(go version); Node: $(node --version); npm: $(npm --version)"
echo "Control: $(git -C "$root" rev-parse HEAD)"
echo "ElXray: $(git -C "$core" rev-parse HEAD)"
echo "ElX-ui: $(git -C "$panel" rev-parse HEAD)"

# Control local suite owns a disposable PostgreSQL container when no DSN is
# passed, and it tests signed policy, two nodes, VLESS, restart and denial.
step "Control + ElXray integration and live multi-node E2E" \
    bash "$root/scripts/elx-test-local.sh"

step "ElXray entire Go test tree" \
    bash -c 'cd "$1" && go test -count=1 -timeout 30m ./...' bash "$core"
step "ElXray full go vet" \
    bash -c 'cd "$1" && go vet ./...' bash "$core"
step "ElXray Python fixture regressions" \
    bash -c 'cd "$1" && python3 -m unittest discover -s testing/subscriptionrate -p "test_*.py" -v' bash "$core"

# The upstream benchmark uses known fixed localhost ports and refuses to
# commandeer user processes that already occupy them.
scratch=$(mktemp -d)
cleanup() {
    rm -rf -- "$scratch"
}
trap cleanup EXIT
step "Build ElXray benchmark binary" \
    bash -c 'cd "$1" && go build -o "$2/elxray" ./main' bash "$core" "$scratch"
step "ElXray runtime throughput and subscription-policy smoke" \
    python3 "$core/testing/subscriptionrate/local_smoke.py" \
    --xray "$scratch/elxray"

step "Install ElX-ui pinned frontend dependencies" \
    bash -c 'cd "$1/frontend" && npm ci' bash "$panel"
step "ElX-ui complete local verify gate" \
    bash -c 'cd "$1" && make verify' bash "$panel"
step "ElX-ui race detector" \
    bash -c 'cd "$1" && make race' bash "$panel"
step "ElX-ui master + node process E2E" \
    bash -c 'cd "$1" && make node-e2e' bash "$panel"
step "ElX-ui vulnerability analysis" \
    bash -c 'cd "$1" && make vulncheck' bash "$panel"

echo 'PASS: full ElX three-repository verification'
