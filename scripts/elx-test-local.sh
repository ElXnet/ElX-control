#!/usr/bin/env bash
# Runs the current ElX integration tests on Linux or WSL.
set -euo pipefail

# WSL --exec starts a non-login shell, which may omit Snap and manual Go paths.
# Keep PATH portable rather than requiring changes to a user's shell profile.
for go_bin_dir in /snap/bin /usr/local/go/bin; do
    if [[ -x "$go_bin_dir/go" && ":$PATH:" != *":$go_bin_dir:"* ]]; then
        export PATH="$go_bin_dir:$PATH"
    fi
done

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
core=$(cd -- "${ELXRAY_SOURCE:-$root/../ElXray}" && pwd)
for tool in go git openssl python3 gcc; do
    command -v "$tool" >/dev/null || { echo "MISSING: $tool (install in WSL Ubuntu)" >&2; exit 1; }
    echo "OK: $tool"
done
echo "Go version: $(go version)"
if [[ -z "${ELX_CONTROL_POSTGRES_DSN:-}" ]]; then
    command -v docker >/dev/null || { echo 'MISSING: docker (enable Docker Desktop WSL integration)' >&2; exit 1; }
    if ! docker info >/dev/null 2>&1; then
        echo 'Docker Engine unavailable: start Docker Desktop and enable Settings > Resources > WSL Integration for Ubuntu.' >&2
        exit 1
    fi
    echo 'OK: Docker Engine'
fi

work=$(mktemp -d)
container=
cleanup() {
    local result=$?
    if [[ -n "$container" ]]; then
        docker rm -f "$container" >/dev/null || true
    fi
    if (( result == 0 )); then
        find "$work" -depth -delete
    else
        echo "Local test logs: $work" >&2
    fi
}
trap cleanup EXIT

if [[ -z "${ELX_CONTROL_POSTGRES_DSN:-}" ]]; then
    command -v docker >/dev/null || { echo 'Docker or a disposable ELX_CONTROL_POSTGRES_DSN is required' >&2; exit 1; }
    container=$(docker run --rm -d -p 127.0.0.1::5432 \
        -e POSTGRES_USER=elx -e POSTGRES_PASSWORD=elx_local_test \
        -e POSTGRES_DB=elx_test postgres:18)
    ready=false
    for _ in {1..60}; do
        if docker exec "$container" pg_isready -h 127.0.0.1 -U elx -d elx_test >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 1
    done
    if [[ "$ready" != true ]]; then
        docker logs "$container" >&2
        exit 1
    fi
    addr=$(docker port "$container" 5432/tcp)
    export ELX_CONTROL_POSTGRES_DSN="host=127.0.0.1 port=${addr##*:} user=elx dbname=elx_test password=elx_local_test sslmode=disable"
fi
export ELX_TEST_POSTGRES_DSN="$ELX_CONTROL_POSTGRES_DSN"

echo "ElX-control revision: $(git -C "$root" rev-parse --short HEAD)"
echo "ElXray revision: $(git -C "$core" rev-parse --short HEAD)"
export ELXRAY_BIN="$work/elxray" ELX_CONTROL_BIN="$work/elx-control"
export TMPDIR="$work"
(
    cd "$core"
    go test -race -count=1 -timeout 180s ./common/sessionfence ./common/subscriptionrate ./app/policy/... ./app/dispatcher ./proxy/vless/inbound
    go build -o "$ELXRAY_BIN" ./main
)
(
    cd "$root"
    go test -race -count=1 -timeout 180s ./internal/elxcontrol/... ./cmd/elx-control
    go build -o "$ELX_CONTROL_BIN" ./cmd/elx-control
    bash scripts/elx-policy-smoke.sh
    python3 scripts/elx-vless-stop-smoke.py
    python3 tests/e2e/test_multinode.py
    python3 tests/e2e/test_rate_partition.py
    python3 tests/e2e/test_lease_partition.py
    python3 tests/e2e/test_live_scheduler.py
    python3 tests/e2e/test_live_fup_scheduler.py
)
echo 'PASS: ElX local suite'
