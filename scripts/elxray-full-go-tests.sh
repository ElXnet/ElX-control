#!/usr/bin/env bash
# Run ElXray's Go test tree with verified upstream fixtures and explicit
# separation between deterministic tests and tests using public Internet.
set -Eeuo pipefail

core=$(cd -- "${1:?usage: elxray-full-go-tests.sh PATH_TO_ELXRAY}" && pwd)
cd "$core"
mkdir -p resources

# Mirror the official ElXray CI prepare-assets action. NEVER use arbitrary
# unverified geodata or silently ignore failed downloads / mismatched hashes.
for item in 'geoip/geoip-lite geoip' 'geosite/geosite geosite'; do
    read -r remote local <<< "$item"
    base="https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/${remote}.dat"
    file="resources/${local}.dat"
    checksum="$file.sha256sum"
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 120 \
        "$base" --output "$file"
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 120 \
        "$base.sha256sum" --output "$checksum"
    digest=$(awk '{print $1}' "$checksum")
    if [[ ! "$digest" =~ ^[a-fA-F0-9]{64}$ ]]; then
        echo "FAIL: invalid published SHA256 for $file" >&2
        exit 1
    fi
    printf '%s  %s\n' "$digest" "$file" | sha256sum --check -
done

if [[ "${ELX_EXTERNAL_NETWORK_TESTS:-0}" == "1" ]]; then
    echo 'Running ALL ElXray Go tests, including Internet-dependent DNS/ECH/REALITY tests.'
    echo 'Public endpoints may time out. A failure is still a test failure.'
    go test -count=1 -timeout 30m ./...
else
    # These upstream tests depend on live public DNS, ECH endpoints or a
    # particular Internet route (e.g., google.com:443 for REALITY). On WSL
    # with a localhost Windows proxy they can hang or panic even when local
    # ElX network/data-plane tests are healthy. Skip them ONLY in the local
    # deterministic gate; explicit opt-in above always runs them.
    skip='^(TestECHDial|TestDOHNameServer.*|TestQUICNameServer.*|TestTCPLocalNameServer.*|TestLocalNameServer|TestVlessXtlsVisionReality|TestVlessRealityFingerprints)$'
    echo 'Running deterministic ElXray Go tests with checked geodata assets.'
    echo "SKIPPED (requires public network): $skip"
    echo 'Opt in to the public-network tests: ELX_EXTERNAL_NETWORK_TESTS=1'
    go test -count=1 -timeout 15m -skip "$skip" ./...
fi
