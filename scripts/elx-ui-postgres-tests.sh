#!/usr/bin/env bash
# Run the panel's live PostgreSQL CI cases; skipped or renamed cases fail the gate.
set -Eeuo pipefail
panel=$(cd -- "${1:?usage: elx-ui-postgres-tests.sh PATH_TO_ELX_UI}" && pwd)
cd "$panel"
work=$(mktemp -d)
container=
cleanup() {
    local result=$?
    if [[ -n "$container" ]]; then
        if (( result != 0 )); then docker logs "$container" >&2 || true; fi
        docker rm -f "$container" >/dev/null || true
    fi
    if (( result == 0 )); then rm -rf -- "$work"; else echo "PostgreSQL test logs: $work" >&2; fi
}
trap cleanup EXIT
if [[ -n "${XUI_DB_DSN:-}" || -n "${XUI_TEST_PG_DSN:-}" ]]; then
    if [[ -z "${XUI_DB_DSN:-}" || -z "${XUI_TEST_PG_DSN:-}" ]]; then
        echo 'Set both XUI_DB_DSN and XUI_TEST_PG_DSN to separate disposable panel databases, or neither.' >&2
        exit 1
    fi
else
    command -v docker >/dev/null || { echo 'Docker or both disposable panel PostgreSQL DSNs are required' >&2; exit 1; }
    container=$(docker run --rm -d -p 127.0.0.1::5432 \
        -e POSTGRES_USER=elx -e POSTGRES_PASSWORD=elx_panel_test postgres:16)
    ready=false
    for _ in {1..60}; do
        if docker exec "$container" pg_isready -h 127.0.0.1 -U elx -d postgres >/dev/null 2>&1; then ready=true; break; fi
        sleep 1
    done
    if [[ "$ready" != true ]]; then echo 'Panel PostgreSQL did not become ready' >&2; exit 1; fi
    docker exec "$container" psql -U elx -d postgres -v ON_ERROR_STOP=1 \
        -c 'CREATE DATABASE xui_durable' -c 'CREATE DATABASE xui_scratch'
    addr=$(docker port "$container" 5432/tcp)
    export XUI_DB_DSN="host=127.0.0.1 port=${addr##*:} user=elx password=elx_panel_test dbname=xui_durable sslmode=disable"
    export XUI_TEST_PG_DSN="host=127.0.0.1 port=${addr##*:} user=elx password=elx_panel_test dbname=xui_scratch sslmode=disable"
fi
export XUI_DB_TYPE=postgres
make dist-stub
run_tests() {
    local package=$1
    shift
    local regex log
    regex=$(IFS='|'; echo "$*")
    log="$work/$(echo "$package" | tr / _).log"
    go test -count=1 -timeout 10m -v "$package" -run "^($regex)$" | tee "$log"
    python3 - "$log" "$@" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
passed = set(re.findall(r'^--- PASS: (\S+) \(', text, re.MULTILINE))
missing = set(sys.argv[2:]) - passed
if missing:
    sys.exit('FAIL: PostgreSQL cases did not pass (missing, skipped or failed): ' + ', '.join(sorted(missing)))
PY
}
run_tests ./internal/web/service \
    TestAddInbound_PostgresCommitFailureMakesNoRuntimeCall \
    TestUpdateInbound_PostgresCommitFailureMakesNoRuntimeCall \
    TestSyncInboundClientsOnPostgres \
    TestSetClientLimitHwidIsSerializedWithSyncInbound \
    TestClientStatsIdentitiesPostgres \
    TestClientIpSyncPostgres \
    TestGlobalTrafficHeartbeatPostgres \
    TestGetClientTrafficTgBot_IndexedPostgres \
    TestGetClientTrafficTgBot_SettingsSerializationStyles
run_tests ./internal/web/job TestClientIpSyncPostgresScanner
run_tests ./internal/web/service/outbound TestAddTrafficReturnsDeferredCommitFailure
run_tests ./internal/database \
    TestHostAutoMigrateCreatesColumns_Postgres \
    TestMigrate_Postgres \
    TestClientWeeklyRenewMigration_Postgres \
    TestMigrate_LegacyBooleanVerifyPeerCertByNameIsBlanked_Postgres \
    TestClientKeepAlivePostgresMigrationPreservesLegacyScalars \
    TestPostgresModelSettled_TracksSchemaPresence \
    TestMigrateData_CompositeKeyTableLargerThanBatch \
    TestMigrateData_PreservesFalseDefaultedColumns \
    TestMigrateData_FailedCopyLeavesDestinationUntouched \
    TestClientHwidSchemaPostgres
run_tests ./internal/sub TestSubHosts_Postgres
echo 'PASS: ElX-ui live PostgreSQL durability and migration cases'
