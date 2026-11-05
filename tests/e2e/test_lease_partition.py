#!/usr/bin/env python3
"""End-to-end signed 15-second lease failure on real VLESS connections.

Tests two live ElXray cores, separate node agents, a real Control policy
server, real PostgreSQL grants, and *mandatory* signed Control leases.
"""
from pathlib import Path
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from test_multinode import Lab, command, require, wait_for


class LeasedLab(Lab):
    def __init__(self, folder):
        super().__init__(folder)
        self.entitlement = str(uuid.uuid4())
        self.lease_seed = folder / "control-lease-seed.key"
        self.lease_seed.write_text(secrets.token_hex(32), encoding="ascii")
        self.lease_seed.chmod(0o600)
        self.lease_public = command(
            [self.control, "policy-public-key", self.lease_seed]
        ).stdout.strip()
        # The master trusts both bindings; each node agent may request
        # leases only for its own locally provisioned binding.
        self.node_manifests = []
        import json
        shared = json.loads(self.manifest.read_text(encoding="utf-8"))
        for i in range(2):
            file = folder / f"node-{i}-binding.json"
            file.write_text(json.dumps([shared[i]]), encoding="utf-8")
            file.chmod(0o600)
            self.node_manifests.append(file)

    def env(self, *, node=None, cert=None):
        env = super().env(node=node, cert=cert)
        env["ELX_CONTROL_LEASE_SEED_FILE"] = str(self.lease_seed)
        if node is not None:
            env["ELX_POLICY_BINDING"] = str(self.node_manifests[node])
            env["ELXRAY_REQUIRE_CONTROL_LEASE"] = "1"
            env["ELXRAY_CONTROL_LEASE_PUBLIC_KEY"] = self.lease_public
            env["ELXRAY_CONTROL_LEASE_NODE_UUID"] = self.node_ids[node]
            env["ELX_AGENT_LEASE_REQUIRED"] = "1"
        return env

    def seed(self):
        boots = [self.usage(i)["Incarnation"] for i in range(2)]
        root = Path(__file__).resolve().parents[2]
        arguments = [
            self.entitlement, self.resource_id,
            self.node_ids[0], boots[0], self.keys[0],
            self.node_ids[1], boots[1], self.keys[1],
        ]
        result = subprocess.run(
            ["go", "run", "./tests/e2e/seed_lease.go", *arguments],
            cwd=root, env=self.env(), capture_output=True, text=True,
            timeout=120, check=False,
        )
        require(result.returncode == 0,
                f"lease fixture not provisioned: {result.stderr[-1200:]}")


def connect_live(lab, node):
    connection = lab.connect(node)
    try:
        connection.settimeout(3)
        lab.ping(connection, f"live-lease-node-{node}".encode())
        return connection
    except BaseException:
        connection.close()
        raise


def eventually_live(lab, node):
    def probe():
        connection = connect_live(lab, node)
        return connection
    return wait_for(f"verified Control lease on node {node}", probe,
                    lab.processes, timeout=28)


def assert_denied(lab, node):
    try:
        with lab.connect(node) as connection:
            connection.settimeout(2)
            lab.ping(connection, b"must-not-pass-without-a-lease")
    except (OSError, AssertionError, socket.timeout):
        return
    raise AssertionError(f"node {node} passed VPN traffic after lease expiry")


def run():
    for required in ("ELXRAY_BIN", "ELX_CONTROL_BIN", "ELX_CONTROL_POSTGRES_DSN"):
        require(os.environ.get(required), f"missing {required}")
    with tempfile.TemporaryDirectory(prefix="elx-signed-lease-e2e-") as temporary:
        lab = None
        connections = []
        try:
            lab = LeasedLab(Path(temporary))
            lab.start()
            # A managed paid profile must NOT transmit before Control
            # has granted a signed lease for the correct node/core.
            for node in range(2):
                assert_denied(lab, node)
            lab.seed()
            for node in range(2):
                lab.start_agent(node)
            for node in range(2):
                connections.append(eventually_live(lab, node))
            print("PASS: both VPN nodes deny traffic before signed Control leases "
                  "and admit only after PostgreSQL-backed lease approval", flush=True)

            # Simulate a network partition of the Control mTLS authority.
            # No signed renewal is possible; both previously established
            # *idle* VPN sessions must be closed after the 15s lease bound.
            lab.stop("control")
            for node, connection in enumerate(connections):
                lab.ping(connection, f"before-expiry-{node}".encode())
            time.sleep(18)
            for node, connection in enumerate(connections):
                connection.settimeout(2)
                try:
                    connection.sendall(b"expired-session")
                    data = connection.recv(32)
                    require(not data,
                            f"node {node} kept its prior VPN session alive past lease expiry")
                except (ConnectionResetError, BrokenPipeError):
                    pass
                assert_denied(lab, node)
            print("PASS: Control network partition expires both mandatory "
                  "15-second leases, closes idle sessions and rejects new VPN payload",
                  flush=True)

            # Restore the identical Control trust anchor and authoritative DB.
            # Old sockets remain gone; only fresh handshakes may reconnect.
            lab.spawn("control", [lab.control, "serve-policy"],
                      env=lab.env(cert="control"))
            for node in range(2):
                with eventually_live(lab, node) as connection:
                    lab.ping(connection, f"renewed-node-{node}".encode())
            print("PASS: authentic Control authority recovery permits new "
                  "connections on both nodes without reviving expired sockets",
                  flush=True)
        except BaseException:
            if lab is not None:
                for path in sorted(Path(temporary).glob("*.log")):
                    print(f"--- {path.name} ---", file=sys.stderr)
                    print(path.read_text(errors="replace")[-3000:], file=sys.stderr)
            raise
        finally:
            for connection in connections:
                connection.close()
            if lab is not None:
                lab.close()


if __name__ == "__main__":
    try:
        run()
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError) as error:
        sys.exit(f"FAIL: signed lease network-partition E2E: {error}")
