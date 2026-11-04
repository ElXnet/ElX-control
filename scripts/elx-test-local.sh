#!/usr/bin/env bash
# Runs the current ElX integration tests on Linux or WSL.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
core=$(cd -- "${ELXRAY_SOURCE:-$root/../ElXray}" && pwd)
for tool in go git openssl python3; do
    command -v "$tool" >/dev/null || { echo "Required command: $tool" >&2; exit 1; }
done

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

echo "ElX-ui revision: $(git -C "$root" rev-parse --short HEAD)"
echo "ElXray revision: $(git -C "$core" rev-parse --short HEAD)"
export ELXRAY_BIN="$work/elxray" ELX_CONTROL_BIN="$work/elx-control"
export TMPDIR="$work"
(
    cd "$core"
    go test -race -count=1 ./common/subscriptionrate ./app/policy/... ./app/dispatcher ./proxy/vless/inbound
    go build -o "$ELXRAY_BIN" ./main
)
(
    cd "$root"
    go test -race -count=1 ./internal/elxcontrol/... ./cmd/elx-control
    go build -o "$ELX_CONTROL_BIN" ./cmd/elx-control
    bash scripts/elx-policy-smoke.sh
    python3 scripts/elx-vless-stop-smoke.py
)
echo 'PASS: ElX local suite'
