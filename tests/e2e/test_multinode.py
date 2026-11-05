#!/usr/bin/env python3
"""Two real ElXray nodes + two VLESS/SOCKS clients + Control journal/agents.

Runs only on 127.0.0.1 with a disposable PostgreSQL DSN supplied by the
caller. No production sockets, accounts or VPS nodes are touched.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def command(args, *, env=None, timeout=15, success=True):
    result = subprocess.run(
        [str(arg) for arg in args], env=env, text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"command {args[:3]} returned {result.returncode}; "
            f"stdout={result.stdout[-900:]!r}; stderr={result.stderr[-900:]!r}"
        )
    return result


def available_ports(count):
    # Reserve simultaneously, so every assigned port is distinct.
    reservations = [socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    for _ in range(count)]
    try:
        for sock in reservations:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in reservations]
    finally:
        for sock in reservations:
            sock.close()


def wait_for(description, check, processes, timeout=20):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        for name, proc in processes.items():
            if proc.poll() is not None:
                raise AssertionError(f"{name} exited unexpectedly: {proc.returncode}")
        try:
            result = check()
            if result:
                return result
        except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as exc:
            error = exc
        time.sleep(0.08)
    raise AssertionError(f"timeout waiting for {description}; last error: {error}")


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            break
        data.extend(block)
    return bytes(data)


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(6)
        try:
            while True:
                block = self.request.recv(16384)
                if not block:
                    return
                self.request.sendall(block)
        except (OSError, ConnectionError):
            return


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Lab:
    def __init__(self, folder):
        self.folder = folder
        self.core = os.environ["ELXRAY_BIN"]
        self.control = os.environ["ELX_CONTROL_BIN"]
        require(os.environ.get("ELX_CONTROL_POSTGRES_DSN"),
                "a disposable ELX_CONTROL_POSTGRES_DSN is required")
        self.base_env = os.environ.copy()
        # Fail closed rather than accidentally inheriting operator lease config.
        self.base_env.pop("ELX_AGENT_LEASE_REQUIRED", None)
        self.processes = {}
        self.handles = []
        self.ports = available_ports(7)
        self.control_port = self.ports[0]
        self.api_ports = self.ports[1:3]
        self.vless_ports = self.ports[3:5]
        self.socks_ports = self.ports[5:7]
        self.node_ids = [str(uuid.uuid4()) for _ in range(2)]
        self.resource_id = str(uuid.uuid4())
        self.user_ids = [str(uuid.uuid4()) for _ in range(2)]
        self.echo = EchoServer(("127.0.0.1", 0), EchoHandler)
        self.echo_thread = threading.Thread(target=self.echo.serve_forever, daemon=True)
        self.echo_thread.start()
        self.destination = self.echo.server_address[1]
        self.ca = folder / "ca.pem"
        self.manifest = folder / "binding.json"
        self.keys = []
        self.write_configs()
        self.make_certificates()
        self.write_manifest()

    def write_configs(self):
        for i in range(2):
            state = self.folder / f"node-{i}-state.json"
            state.write_text('{"Version":1}', encoding="utf-8")
            secret = Path(str(state) + ".key")
            secret.write_text(secrets.token_hex(32), encoding="ascii")
            secret.chmod(0o600)
            key = command([self.control, "policy-public-key", secret]).stdout.strip()
            require(len(base64.b64decode(key, validate=True)) == 32,
                    "unexpected core public key size")
            self.keys.append(key)
            server = {
                "log": {"loglevel": "warning"},
                "api": {"tag": "api", "listen": f"127.0.0.1:{self.api_ports[i]}",
                        "services": ["SubscriptionService"]},
                "inbounds": [{"listen": "127.0.0.1", "port": self.vless_ports[i],
                              "protocol": "vless",
                              "settings": {"decryption": "none", "clients": [
                                  {"id": self.user_ids[i], "email": "lab"}]}}],
                "outbounds": [{"protocol": "freedom", "settings": {
                    "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"],
                                    "port": str(self.destination)}]}}],
                "policy": {"requireSubscription": True, "subscriptions": {
                    "lab": {"emails": ["lab"], "uplinkBps": 250000,
                            "downlinkBps": 250000}}},
            }
            client = {
                "log": {"loglevel": "warning"},
                "inbounds": [{"listen": "127.0.0.1", "port": self.socks_ports[i],
                              "protocol": "socks", "settings": {"auth": "noauth"}}],
                "outbounds": [{"protocol": "vless", "settings": {"vnext": [{
                    "address": "127.0.0.1", "port": self.vless_ports[i],
                    "users": [{"id": self.user_ids[i], "encryption": "none"}]}]}}],
            }
            (self.folder / f"node-{i}.json").write_text(json.dumps(server), encoding="utf-8")
            (self.folder / f"client-{i}.json").write_text(json.dumps(client), encoding="utf-8")

    def make_certificates(self):
        def openssl(*args):
            command(["openssl", *args])
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                "-subj", "/CN=ElX-E2E-CA", "-keyout", self.folder / "ca.key",
                "-out", self.ca)
        specs = [("control", "serverAuth", "IP:127.0.0.1"),
                 ("node0", "clientAuth", f"URI:spiffe://elxnet/node/{self.node_ids[0]}"),
                 ("node1", "clientAuth", f"URI:spiffe://elxnet/node/{self.node_ids[1]}"),
                 ("outsider", "clientAuth", f"URI:spiffe://elxnet/node/{uuid.uuid4()}")]
        for name, usage, san in specs:
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-nodes", "-subj", f"/CN={name}",
                    "-keyout", self.folder / f"{name}.key",
                    "-out", self.folder / f"{name}.csr")
            ext = self.folder / f"{name}.ext"
            ext.write_text(f"extendedKeyUsage={usage}\nsubjectAltName={san}\n",
                           encoding="ascii")
            openssl("x509", "-req", "-in", self.folder / f"{name}.csr",
                    "-CA", self.ca, "-CAkey", self.folder / "ca.key",
                    "-CAcreateserial", "-days", "1", "-extfile", ext,
                    "-out", self.folder / f"{name}.pem")

    def write_manifest(self):
        bindings = [
            {"Target": {"NodeID": self.node_ids[i], "ResourceID": self.resource_id},
             "Subscription": "lab", "Epoch": 1, "PublicKey": self.keys[i]}
            for i in range(2)
        ]
        self.manifest.write_text(json.dumps(bindings), encoding="utf-8")
        self.manifest.chmod(0o600)

    def env(self, *, node=None, cert=None):
        env = self.base_env.copy()
        env.update({
            "ELX_POLICY_CONTROL": f"127.0.0.1:{self.control_port}",
            "ELX_POLICY_LISTEN": f"127.0.0.1:{self.control_port}",
            "ELX_POLICY_BINDING": str(self.manifest),
            "ELX_TLS_CA": str(self.ca),
        })
        if cert is not None:
            env["ELX_TLS_CERT"] = str(self.folder / f"{cert}.pem")
            env["ELX_TLS_KEY"] = str(self.folder / f"{cert}.key")
        if node is not None:
            env["ELXRAY_POLICY_LOOPBACK"] = f"127.0.0.1:{self.api_ports[node]}"
            env["ELXRAY_POLICY_STATE"] = str(self.folder / f"node-{node}-state.json")
        return env

    def spawn(self, name, args, *, env):
        handle = (self.folder / f"{name}.log").open("a", encoding="utf-8")
        self.handles.append(handle)
        self.processes[name] = subprocess.Popen(
            [str(x) for x in args], env=env, stdout=handle,
            stderr=subprocess.STDOUT, start_new_session=True,
        )

    def stop(self, name):
        process = self.processes.pop(name, None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def close(self):
        for name in list(self.processes):
            self.stop(name)
        self.echo.shutdown()
        self.echo.server_close()
        for handle in self.handles:
            handle.close()

    def get_policy(self, node):
        result = command([self.core, "api", "subscription-get",
                          f"--server=127.0.0.1:{self.api_ports[node]}",
                          "--id=lab"], timeout=5)
        return json.loads(result.stdout)

    def await_revision(self, node, revision, *, disabled=False):
        def check():
            value = self.get_policy(node)
            return value if int(value["revision"]) == revision and bool(value.get("disabled", False)) == disabled else None
        return wait_for(f"node {node} policy revision={revision} disabled={disabled}",
                        check, self.processes)

    def enqueue(self, node, expected, up, down, *, disabled=False, operation=None,
                success=True):
        op = operation or str(uuid.uuid4())
        result = command([self.control, "enqueue-policy",
                          "-node", self.node_ids[node], "-resource", self.resource_id,
                          "-operation", op, "-expected", str(expected),
                          "-up", str(up), "-down", str(down),
                          f"-disabled={str(disabled).lower()}"],
                         env=self.env(), success=success)
        return op, result

    def usage(self, node, *, key=None, success=True):
        result = command([self.control, "read-usage", "lab", key or self.keys[node]],
                         env=self.env(node=node), success=success)
        return json.loads(result.stdout) if success else None

    def connect(self, node):
        client = socket.create_connection(("127.0.0.1", self.socks_ports[node]), timeout=3)
        client.settimeout(3)
        try:
            client.sendall(b"\x05\x01\x00")
            require(read_exact(client, 2) == b"\x05\x00", f"SOCKS auth failed, node {node}")
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"
                           + self.destination.to_bytes(2, "big"))
            reply = read_exact(client, 10)
            require(reply[:2] == b"\x05\x00", f"SOCKS connect failed, node {node}: {reply!r}")
            return client
        except BaseException:
            client.close()
            raise

    @staticmethod
    def ping(sock, message):
        sock.sendall(message)
        require(read_exact(sock, len(message)) == message, "VLESS payload mismatch")

    def start(self):
        for i in range(2):
            self.spawn(f"node{i}", [self.core, "run", "-c", self.folder / f"node-{i}.json"],
                       env=self.env(node=i))
            self.spawn(f"client{i}", [self.core, "run", "-c", self.folder / f"client-{i}.json"],
                       env=self.env())
        self.spawn("control", [self.control, "serve-policy"], env=self.env(cert="control"))
        for i in range(2):
            self.await_revision(i, 1)
            def socks_ready(port=self.socks_ports[i]):
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            wait_for(f"node {i} socks listener", socks_ready, self.processes)
        def control_ready():
            with socket.create_connection(("127.0.0.1", self.control_port), timeout=0.5):
                return True
        wait_for("Control mTLS listener", control_ready, self.processes)

    def start_agent(self, node):
        self.spawn(f"agent{node}", [self.control, "serve-agent", "-interval", "200ms"],
                   env=self.env(node=node, cert=f"node{node}"))


def test_multinode():
    for name in ("ELXRAY_BIN", "ELX_CONTROL_BIN", "ELX_CONTROL_POSTGRES_DSN"):
        require(os.environ.get(name), f"set {name}")
    with tempfile.TemporaryDirectory(prefix="elx-multinode-e2e-") as tmp:
        lab = None
        try:
            lab = Lab(Path(tmp))
            lab.start()
            # Establish both flows BEFORE changing any Control-issued policy.
            with lab.connect(0) as flow0, lab.connect(1) as flow1:
                lab.ping(flow0, b"first-node")
                lab.ping(flow1, b"second-node")
                # Signed transfer counters may settle on connection close.
                # Keep the two established flows alive, and complete separate
                # short flows before asserting the observed traffic.
                for i in range(2):
                    with lab.connect(i) as short_flow:
                        lab.ping(short_flow, f"signed-usage-node-{i}".encode())
                for i in range(2):
                    def signed_bytes(node=i):
                        proof = lab.usage(node)
                        return proof if proof["UpBytes"] > 0 and proof["DownBytes"] > 0 else None
                    wait_for(f"signed usage on node {i}", signed_bytes, lab.processes)
                    other = lab.keys[1 - i]
                    lab.usage(i, key=other, success=False)

                op0, _ = lab.enqueue(0, 0, 150000, 160000)
                lab.enqueue(1, 0, 170000, 180000)
                # Unauthorized/misrouted agents MUST NOT consume a pending command.
                wrong = command([lab.control, "apply-policy"],
                                env=lab.env(node=0, cert="outsider"), success=False)
                require("PermissionDenied" in wrong.stderr,
                        "foreign mTLS node identity was not rejected")
                wrong_core = command([lab.control, "apply-policy"],
                                     env=lab.env(node=0, cert="node1"), success=False)
                require("does not match assigned core" in wrong_core.stderr,
                        "node-1 command could target node-0 core")
                # A changed payload with the same journal operation is not an idempotent retry.
                lab.enqueue(0, 0, 160000, 160000, operation=op0, success=False)
                for i in range(2):
                    lab.start_agent(i)
                p0 = lab.await_revision(0, 2)
                p1 = lab.await_revision(1, 2)
                require(int(p0["uplinkBps"]) == 150000 and int(p0["downlinkBps"]) == 160000,
                        "node 0 received wrong rates")
                require(int(p1["uplinkBps"]) == 170000 and int(p1["downlinkBps"]) == 180000,
                        "node 1 received wrong rates")
                # A reduction must not disconnect an already established idle flow.
                lab.ping(flow0, b"live-after-reduction-0")
                lab.ping(flow1, b"live-after-reduction-1")
                print("PASS: two live VLESS nodes; signed traffic; rates changed without disconnect")
                # Simultaneous independent client connections exercise both
                # cores while policy revisions are live. This is concurrency
                # acceptance, NOT a proof of purchased global rate limits.
                def transfer_many(node, failures):
                    try:
                        for index in range(4):
                            with lab.connect(node) as parallel:
                                payload = (f"node-{node}-client-{index}-".encode() * 64)
                                lab.ping(parallel, payload)
                    except BaseException as exc:
                        failures.append((node, str(exc)))
                failures = []
                workers = [threading.Thread(target=transfer_many, args=(node, failures))
                           for node in range(2) for _ in range(3)]
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join(timeout=15)
                require(not any(worker.is_alive() for worker in workers),
                        "parallel VLESS transfers stalled")
                require(not failures, f"parallel VLESS transfer failures: {failures}")
                print("PASS: concurrent VLESS client flows across two live nodes")

                lab.enqueue(0, 1, 150000, 160000, disabled=True)
                lab.await_revision(0, 3, disabled=True)
                # The other node remains reachable even when node 0 is disabled.
                lab.ping(flow1, b"other-node-still-alive")
                flow0.settimeout(2)
                try:
                    require(flow0.recv(1) == b"", "disabled node kept established flow open")
                except ConnectionResetError:
                    pass
                # New traffic on the disabled node must not pass payload.
                try:
                    with lab.connect(0) as denied:
                        denied.sendall(b"denied-payload")
                        require(read_exact(denied, 14) == b"",
                                "disabled node passed new payload")
                except (ConnectionResetError, BrokenPipeError):
                    pass
                print("PASS: node-local disable drains established flow and blocks new payload")

            before = lab.usage(0)["Incarnation"]
            lab.stop("node0")
            lab.spawn("node0", [lab.core, "run", "-c", lab.folder / "node-0.json"],
                      env=lab.env(node=0))
            lab.await_revision(0, 3, disabled=True)
            require(lab.usage(0)["Incarnation"] != before,
                    "core restart reused old signed incarnation")
            print("PASS: durable disabled policy and new incarnation after core restart")

            # Simulate a Control-to-agent network partition by removing only
            # the Control listener. Both live VPN cores must keep forwarding
            # under their last accepted policies; no agent may invent a new
            # revision or grant while disconnected.
            with lab.connect(1) as partition_flow:
                lab.ping(partition_flow, b"before-control-partition")
                lab.stop("control")
                lab.ping(partition_flow, b"through-control-partition")
                require(int(lab.get_policy(1)["revision"]) == 2,
                        "agent changed policy while Control was unreachable")
                # Queue an update durably while the transport is unavailable.
                lab.enqueue(1, 1, 120000, 130000)
                time.sleep(0.7)
                require(int(lab.get_policy(1)["revision"]) == 2,
                        "offline agent applied a queued policy without Control")
                lab.spawn("control", [lab.control, "serve-policy"],
                          env=lab.env(cert="control"))
                partition_policy = lab.await_revision(1, 3)
                require(int(partition_policy["downlinkBps"]) == 130000,
                        "reconnected agent failed to apply durable queued update")
                lab.ping(partition_flow, b"after-control-reconnect")
            print("PASS: Control-agent partition, no speculative grants, queued recovery")

            # Surviving Control restarts must preserve journal revisions.
            lab.stop("control")
            lab.spawn("control", [lab.control, "serve-policy"], env=lab.env(cert="control"))
            lab.enqueue(0, 2, 190000, 200000)
            final = lab.await_revision(0, 4)
            require(int(final["downlinkBps"]) == 200000, "Control failed durable retry")
            with lab.connect(0) as restored:
                lab.ping(restored, b"restored-flow")
            with lab.connect(1) as unaffected:
                lab.ping(unaffected, b"unaffected-flow")
            print("PASS: Control restart; re-enable; both nodes reachable")
            print("PASS: multi-node E2E completed")
        except BaseException:
            if lab is not None:
                for logfile in sorted(Path(tmp).glob("*.log")):
                    print(f"--- {logfile.name} ---", file=sys.stderr)
                    print(logfile.read_text(errors="replace")[-3500:], file=sys.stderr)
            raise
        finally:
            if lab is not None:
                lab.close()


if __name__ == "__main__":
    try:
        test_multinode()
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError) as error:
        sys.exit(f"FAIL: multi-node E2E: {error}")
