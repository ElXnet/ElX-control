#!/usr/bin/env bash
# Run ONLY the P0 FUP/signed-rate-scheduler PostgreSQL acceptance gate in WSL.
# Creates and removes a disposable PostgreSQL Docker container; never touches
# a configured operator/prod database. Logs are saved outside Git checkouts.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
workspace=$(dirname -- "$root")
log_dir="$workspace/test-logs"
mkdir -p -- "$log_dir"
stamp=$(date -u +%Y%m%d-%H%M%S)
log_file="$log_dir/ElX-fup-scheduler-$stamp.log"
container=""

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n "$container" ]]; then
        if (( status != 0 )); then
            echo "===== Disposable PostgreSQL diagnostics ====="
            docker logs --tail 100 "$container" 2>&1 || true
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    if (( status == 0 )); then
        echo "PASS: ElX FUP + attested rate scheduler acceptance"
    else
        echo "FAIL: ElX FUP + attested rate scheduler acceptance (exit $status)"
    fi
    echo "Full test log: $log_file"
    exit "$status"
}
# Capture ALL stdout/stderr including failure diagnostics and the container
# teardown. Bash's pipefail must still report a failing Go test to the user.
exec > >(tee -a "$log_file") 2>&1
trap cleanup EXIT

if (( $# != 0 )); then
    echo "Usage: bash scripts/elx-test-fup.sh"
    exit 2
fi
echo "ElX FUP acceptance: $(date -u +%FT%TZ)"
echo "Control checkout: $root"
echo "Full test log: $log_file"
for tool in go gcc git docker; do
    command -v "$tool" >/dev/null || {
        echo "MISSING: $tool (required in WSL Ubuntu)"
        exit 1
    }
done
if ! docker info >/dev/null 2>&1; then
    echo "Docker Engine is unavailable. Start Docker Desktop and enable WSL Integration for Ubuntu."
    exit 1
fi
echo "Go version: $(go version)"
echo "Control revision: $(git -C "$root" rev-parse HEAD)"

# Ignore any inherited database credentials. A unique docker container with
# elx_test is the ONLY database used by this acceptance runner.
unset ELX_TEST_POSTGRES_DSN ELX_CONTROL_POSTGRES_DSN

echo "Starting disposable PostgreSQL 18 on an assigned loopback port..."
container=$(docker run --rm -d -p 127.0.0.1::5432 \
    -e POSTGRES_USER=elx \
    -e POSTGRES_PASSWORD=elx_fup_test_only \
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
    echo "FAIL: disposable PostgreSQL did not become ready"
    exit 1
fi
address=$(docker port "$container" 5432/tcp)
port="${address##*:}"
if [[ ! "$port" =~ ^[0-9]+$ ]]; then
    echo "FAIL: cannot detect disposable PostgreSQL loopback port: $address"
    exit 1
fi
export ELX_TEST_POSTGRES_DSN="host=127.0.0.1 port=$port user=elx password=elx_fup_test_only dbname=elx_test sslmode=disable"
echo "PostgreSQL ready on 127.0.0.1:$port"

# Keep a focused, explicit acceptance list. A missing test name must fail,
# rather than producing a misleading green 'ok [no tests to run]'.
tests=(
    TestFUPTighteningInterleavesWithAttestedSchedulerAndSignedBarriers
    TestActiveFUPDoesNotBlockReductionOrAllowExpansion
    TestAttestedSchedulerQueuesReductionFirstAndNeverReusesUnprovedCapacity
    TestAttestedSchedulerRequiresFreshCoreProofAndCurrentBudget
    TestSchedulerLeaderFencesFormerOwnerAndExpiredToken
    TestDemandRebalanceResnapshotsTightenedBudget
)
regex="^($(IFS='|'; echo "${tests[*]}"))$"
tmp_output=$(mktemp)
trap 'rm -f -- "$tmp_output"' RETURN

echo "Running ${#tests[@]} PostgreSQL acceptance tests with Go race detector..."
(
    cd "$root"
    go test -race -count=1 -timeout 5m -v ./internal/elxcontrol/journal -run "$regex"
) | tee "$tmp_output"

python3 - "$tmp_output" "${tests[@]}" <<'PY'
import pathlib
import re
import sys

data = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
found = set(re.findall(r"^--- PASS: (\S+) \(", data, re.MULTILINE))
required = set(sys.argv[2:])
missing = sorted(required - found)
if missing:
    sys.exit("FAIL: required acceptance tests missing, skipped or not passed: " + ", ".join(missing))
print(f"PASS: all {len(required)} explicitly required FUP/scheduler tests executed")
PY
