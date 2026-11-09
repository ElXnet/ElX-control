import base64
import json
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import uuid

binary = os.environ['ELXRAY_BIN']
with tempfile.TemporaryDirectory() as tmp:
    processes = []
    control = os.environ['ELX_CONTROL_BIN']
    state = pathlib.Path(tmp) / 'policy'
    state.write_text('{"Version":1}')
    seed = pathlib.Path(str(state) + '.key')
    seed.write_text(secrets.token_hex(32))
    seed.chmod(0o600)
    key = subprocess.check_output([control, 'policy-public-key', str(seed)], text=True).strip()
    echo = socket.socket()
    echo.bind(('127.0.0.1', 0))
    echo.listen()
    def serve():
        while True:
            try:
                conn, _ = echo.accept()
            except OSError:
                return
            def copy(c):
                with c:
                    while data := c.recv(2048):
                        c.sendall(data)
            threading.Thread(target=copy, args=(conn,), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    dest = echo.getsockname()[1]

    # Keep all three reservations until their port numbers are unique.
    reservations = [socket.socket() for _ in range(3)]
    for sock in reservations:
        sock.bind(('127.0.0.1', 0))
    api, vless, socks = (sock.getsockname()[1] for sock in reservations)
    for sock in reservations:
        sock.close()
    user_id = str(uuid.uuid4())
    server = {
        'api': {'tag':'api', 'listen': f'127.0.0.1:{api}', 'services':['SubscriptionService']},
        'inbounds':[{'listen':'127.0.0.1','port':vless,'protocol':'vless',
                     'settings':{'decryption':'none','clients':[{'id':user_id,'email':'lab'}]}}],
        'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32'],'port':str(dest)}]}}],
        'policy':{'requireSubscription':True,'subscriptions':{'lab':{'emails':['lab'],'uplinkBps':10000,'downlinkBps':10000}}},
    }
    client = {
        'inbounds':[{'listen':'127.0.0.1','port':socks,'protocol':'socks','settings':{'auth':'noauth'}}],
        'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':vless,
                     'users':[{'id':user_id,'encryption':'none'}]}]}}],
    }
    def start(name, config):
        path = pathlib.Path(tmp)/f'{name}.json'
        config['log'] = {'loglevel': 'warning'}
        path.write_text(json.dumps(config))
        env = os.environ.copy()
        if name == 'server':
            # Legacy loopback smoke intentionally runs without Control leases.
            # This is NOT the paid managed-node security configuration.
            env['ELXRAY_MODE'] = 'standalone'
            env['ELXRAY_POLICY_STATE'] = str(state)
        p = subprocess.Popen([binary, 'run', '-c', str(path)], env=env)
        processes.append(p)
        return p
    def wait(port):
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', port),timeout=0.1):
                    return
            except OSError:
                time.sleep(0.03)
        raise RuntimeError(f'port {port} did not start')
    def receive(c, size):
        data = bytearray()
        while len(data) < size:
            block = c.recv(size - len(data))
            if not block:
                break
            data.extend(block)
        return bytes(data)

    def connect():
        c = socket.create_connection(('127.0.0.1', socks),timeout=2)
        c.sendall(b'\x05\x01\x00')
        assert receive(c, 2) == b'\x05\x00'
        c.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + dest.to_bytes(2,'big'))
        assert receive(c, 10)[:2] == b'\x05\x00'
        return c
    def roundtrip(c):
        c.sendall(b'ping')
        assert receive(c, 4) == b'ping'
    def update(old, new, disabled):
        subprocess.run([binary,'api','subscription-set',f'--server=127.0.0.1:{api}','--id=lab',
                        f'--expected-revision={old}',f'--revision={new}','--uplink-bps=10000',
                        '--downlink-bps=10000',f'--disabled={str(disabled).lower()}'],check=True,
                       stdout=subprocess.DEVNULL, timeout=3)
    def usage(public_key=key):
        return subprocess.run([control, 'read-usage', 'lab', public_key],
                              env={**os.environ, 'ELXRAY_POLICY_LOOPBACK': f'127.0.0.1:{api}'},
                              capture_output=True, timeout=6)
    def sample():
        result = usage()
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    try:
        server_process = start('server', server)
        start('client',client)
        wait(api)
        wait(socks)
        initial = sample()
        assert (initial['UpBytes'], initial['DownBytes']) == (0, 0)
        wrong_key = base64.b64encode(bytes(32)).decode()
        assert usage(wrong_key).returncode != 0
        with connect() as c:
            roundtrip(c)
            update(1,2,True)
            # The flow is idle here. A writer-side budget check alone cannot close it.
            try:
                assert c.recv(1) == b'', 'idle socket remained open'
            except ConnectionResetError:
                pass
        with connect() as c:
            try:
                c.sendall(b'ping')
                assert receive(c, 4) == b'', 'disabled subscription passed payload'
            except ConnectionResetError:
                pass
        update(2,3,False)
        with connect() as c:
            roundtrip(c)
        # A downstream reader can receive the last bytes before the writer
        # returns and records the successful handoff.
        deadline = time.monotonic() + 2
        counted = sample()
        while counted['DownBytes'] < 8 and time.monotonic() < deadline:
            time.sleep(0.02)
            counted = sample()
        assert (counted['UpBytes'], counted['DownBytes']) == (8, 8), counted
        assert counted['Sequence'] > initial['Sequence']
        assert counted['Incarnation'] == initial['Incarnation']
        server_process.terminate()
        server_process.wait(timeout=5)
        start('server', server)
        wait(api)
        restarted = sample()
        assert restarted['Incarnation'] != counted['Incarnation']
        assert (restarted['UpBytes'], restarted['DownBytes']) == (0, 0)
        print('PASS: signed VLESS payload counters, wrong key rejected, restart changes incarnation')
        print('PASS: VLESS TCP idle connection closed, new traffic denied, re-enable works')
    finally:
        echo.close()
        for p in processes:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=5)
