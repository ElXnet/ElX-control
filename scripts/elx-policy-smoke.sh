#!/usr/bin/env bash
# Requires a disposable PostgreSQL database, openssl, and both binaries.
set -euo pipefail
: "${ELX_CONTROL_POSTGRES_DSN:?set a disposable PostgreSQL DSN}"
: "${ELXRAY_BIN:?set the absolute path to ElXray}"
: "${ELX_CONTROL_BIN:?set the absolute path to elx-control}"
dir=$(mktemp -d)
umask 077
core_pid=
second_pid=
control_pid=
cleanup() {
    local result=$?
    for pid in "$core_pid" "$second_pid" "$control_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if (( result != 0 )); then
        cat "$dir"/{core,second,control}.log 2>/dev/null || true
        echo "Smoke logs: $dir" >&2
    fi
}
trap cleanup EXIT
export ELX_POLICY_CONTROL="127.0.0.1:${ELX_SMOKE_CONTROL_PORT:-15443}"
export ELX_POLICY_LISTEN="$ELX_POLICY_CONTROL"
export ELXRAY_POLICY_LOOPBACK="127.0.0.1:${ELX_SMOKE_CORE_PORT:-15085}"
second_addr="127.0.0.1:${ELX_SMOKE_SECOND_PORT:-15086}"
export ELXRAY_POLICY_STATE="$dir/state.json"
export ELX_POLICY_BINDING="$dir/binding.json"
export ELX_TLS_CA="$dir/ca.pem"

node=$(cat /proc/sys/kernel/random/uuid)
second_node=$(cat /proc/sys/kernel/random/uuid)
second_op=$(cat /proc/sys/kernel/random/uuid)
resource=$(cat /proc/sys/kernel/random/uuid)
op=$(cat /proc/sys/kernel/random/uuid)
next_op=$(cat /proc/sys/kernel/random/uuid)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=ElX-Smoke-CA -keyout "$dir/ca.key" -out "$ELX_TLS_CA" 2>/dev/null
certificate() {
    local name=$1 usage=$2 san=$3
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=$name" -keyout "$dir/$name.key" -out "$dir/$name.csr" 2>/dev/null
    printf 'extendedKeyUsage=%s\nsubjectAltName=%s\n' "$usage" "$san" > "$dir/$name.ext"
    openssl x509 -req -in "$dir/$name.csr" -CA "$ELX_TLS_CA" -CAkey "$dir/ca.key" \
        -CAcreateserial -days 1 -extfile "$dir/$name.ext" -out "$dir/$name.pem" 2>/dev/null
}
certificate control serverAuth IP:127.0.0.1
certificate node clientAuth "URI:spiffe://elxnet/node/$node"
certificate second clientAuth "URI:spiffe://elxnet/node/$second_node"
certificate wrong clientAuth "URI:spiffe://elxnet/node/$(cat /proc/sys/kernel/random/uuid)"
printf '{"Version":1}' > "$ELXRAY_POLICY_STATE"
openssl rand -hex 32 | tr -d '\n' > "$ELXRAY_POLICY_STATE.key"
public_key=$("$ELX_CONTROL_BIN" policy-public-key "$ELXRAY_POLICY_STATE.key")
printf '{"Version":1}' > "$dir/second.json"
openssl rand -hex 32 | tr -d '\n' > "$dir/second.json.key"
second_key=$("$ELX_CONTROL_BIN" policy-public-key "$dir/second.json.key")
printf '[{"Target":{"NodeID":"%s","ResourceID":"%s"},"Subscription":"lab","Epoch":1,"PublicKey":"%s"},{"Target":{"NodeID":"%s","ResourceID":"%s"},"Subscription":"lab","Epoch":1,"PublicKey":"%s"}]\n' \
    "$node" "$resource" "$public_key" "$second_node" "$resource" "$second_key" > "$ELX_POLICY_BINDING"
core_config() {
    printf '{"api":{"tag":"api","listen":"%s","services":["SubscriptionService"]},"policy":{"requireSubscription":true,"subscriptions":{"lab":{"emails":["lab"],"uplinkBps":1000,"downlinkBps":2000}}}}\n' "$1"
}
core_config "$ELXRAY_POLICY_LOOPBACK" > "$dir/core.json"
core_config "$second_addr" > "$dir/second-core.json"

get_policy() {
    "$ELXRAY_BIN" api subscription-get --server="$ELXRAY_POLICY_LOOPBACK" --id=lab
}
start_core() {
    "$ELXRAY_BIN" run -c "$dir/core.json" > "$dir/core.log" 2>&1 &
    core_pid=$!
    for _ in {1..40}; do
        if get_policy > "$dir/readback.json" 2>/dev/null; then return; fi
        kill -0 "$core_pid"
        sleep 0.1
    done
    return 1
}
apply_as() {
    ELX_TLS_CERT="$dir/$1.pem" ELX_TLS_KEY="$dir/$1.key" "$ELX_CONTROL_BIN" apply-policy
}
enqueue() {
    "$ELX_CONTROL_BIN" enqueue-policy -node "${5:-$node}" -resource "$resource" -operation "$1" -expected "$2" -up "$3" -down "$4"
}
start_core
[[ "$(enqueue "$op" 0 300 400)" == 1 ]]
ELX_TLS_CERT="$dir/control.pem" ELX_TLS_KEY="$dir/control.key" \
    "$ELX_CONTROL_BIN" serve-policy > "$dir/control.log" 2>&1 &
control_pid=$!
for _ in {1..40}; do
    if error=$(apply_as wrong 2>&1); then
        echo 'Wrong node certificate was accepted' >&2
        exit 1
    fi
    if [[ "$error" == *PermissionDenied* ]]; then break; fi
    kill -0 "$control_pid"
    sleep 0.1
done
[[ "$error" == *PermissionDenied* ]]

# Simulate a node losing its process before sending ACK, after core commit.
"$ELXRAY_BIN" api subscription-set --server="$ELXRAY_POLICY_LOOPBACK" --id=lab \
    --expected-revision=1 --revision=2 --uplink-bps=300 --downlink-bps=400 --disabled=false >/dev/null
kill "$core_pid"
wait "$core_pid"
core_pid=
start_core
grep -Eq '"revision":[[:space:]]*2' "$dir/readback.json"
grep -Eq '"uplinkBps":[[:space:]]*300' "$dir/readback.json"
grep -Eq '"downlinkBps":[[:space:]]*400' "$dir/readback.json"
apply_as node
[[ "$(enqueue "$next_op" 1 150 250)" == 2 ]]
apply_as node
get_policy > "$dir/readback.json"
grep -Eq '"revision":[[:space:]]*3' "$dir/readback.json"
grep -Eq '"downlinkBps":[[:space:]]*250' "$dir/readback.json"
[[ "$(enqueue "$second_op" 0 700 800 "$second_node")" == 1 ]]
# Node 1 has no commands even while node 2 has a pending policy.
if error=$(apply_as node 2>&1) || [[ "$error" != *NotFound* ]]; then
    echo "Node 1 was able to see node 2's pending policy: $error" >&2
    exit 1
fi
# A misconfigured node 2 agent cannot mutate the first core.
if error=$(apply_as second 2>&1) || [[ "$error" != *"does not match assigned core"* ]]; then
    echo "Expected pre-write key rejection: $error" >&2
    exit 1
fi
ELXRAY_POLICY_STATE="$dir/second.json" "$ELXRAY_BIN" run -c "$dir/second-core.json" > "$dir/second.log" 2>&1 &
second_pid=$!
for _ in {1..40}; do
    if ELXRAY_POLICY_LOOPBACK="$second_addr" get_policy >/dev/null 2>&1; then break; fi
    kill -0 "$second_pid"
    sleep 0.1
done
ELXRAY_POLICY_LOOPBACK="$second_addr" apply_as second
ELXRAY_POLICY_LOOPBACK="$second_addr" get_policy > "$dir/second-readback.json"
grep -Eq '"revision":[[:space:]]*2' "$dir/second-readback.json"
grep -Eq '"downlinkBps":[[:space:]]*800' "$dir/second-readback.json"
get_policy | grep -E '"downlinkBps":[[:space:]]*250'
echo "PASS: mTLS, two nodes, wrong-core rejection, durable restart and replay"
