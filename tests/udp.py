#!/usr/bin/env python3
"""Run real naive SOCKS5 -> patched Caddy HTTP/3 DATAGRAM integration tests.

No system trust settings are changed. A temporary CA is explicitly trusted by
this naive process using --trusted-cert. Requires openssl, Python 3 and both
compiled executables. All listeners and target services are local.
"""
import argparse
import base64
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time


def load_helpers():
    path = Path(__file__).resolve().parents[1] / 'tools/run-udp-tests.py'
    spec = importlib.util.spec_from_file_location('udp_helpers', path)
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    return helpers


H = load_helpers()


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def echo_server(ip):
    sock = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET,
                         socket.SOCK_DGRAM)
    sock.bind((ip, 0))
    sock.settimeout(0.1)
    stop = threading.Event()
    def run():
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(65536)
                sock.sendto(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=1)
        sock.close()


@contextlib.contextmanager
def process(command, directory, logname):
    with open(directory / logname, 'w+') as log:
        env = os.environ.copy()
        env['XDG_CONFIG_HOME'] = str(directory / 'config')
        env['XDG_DATA_HOME'] = str(directory / 'data')
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            log.seek(0)
            text = log.read()
            if proc.returncode not in (0, -15):
                print(f'{logname}:\n{text[-10000:]}')


def wait_listen(proc, port):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f'process exited: {proc.returncode}')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f'listener {port}')


@contextlib.contextmanager
def tcp_echo_server():
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            while True:
                data = self.request.recv(4096)
                if not data:
                    return
                self.request.sendall(data)
    with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler) as server:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


def verify_tcp(local_port, target_port):
    with socket.create_connection(('127.0.0.1', local_port), timeout=5) as tcp:
        tcp.sendall(b'\x05\x01\x00')
        assert H.recv_exact(tcp, 2) == b'\x05\x00'
        tcp.sendall(b'\x05\x01\x00' + H.encode_socks_address('127.0.0.1', target_port))
        reply = H.recv_exact(tcp, 4)
        assert reply[:3] == b'\x05\x00\x00', reply
        H.decode_socks_address(tcp, reply[3])
        payload = b'TCP and Naive padding still work' * 100
        tcp.sendall(payload)
        assert H.recv_exact(tcp, len(payload)) == payload


def packet(host, port, payload):
    return b'\0\0\0' + H.encode_socks_address(host, port) + payload


def exchange(sock, relay, host, port, payload):
    # The local UDP API remains unreliable. A timed retry also allows PMTU
    # discovery to settle without assuming the first datagram is delivered.
    for _ in range(6):
        sock.sendto(packet(host, port, payload), relay)
        try:
            got, _ = sock.recvfrom(65536)
            parsed = H.parse_udp_packet(got)
            if parsed[-1] != payload:
                raise AssertionError(f'payload mismatch: {len(payload)} bytes')
            return
        except socket.timeout:
            continue
    raise AssertionError(f'no UDP reply from {host}:{port}, {len(payload)} bytes')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--naive', required=True, type=Path)
    parser.add_argument('--caddy', required=True, type=Path)
    args = parser.parse_args()
    naive, caddy = str(args.naive.resolve()), str(args.caddy.resolve())
    with tempfile.TemporaryDirectory(prefix='naive-udp-') as tmp:
        directory = Path(tmp)
        cert, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-new', '-x509', '-newkey', 'ec',
                        '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server_port, local_port = free_port(), free_port()
        server_config = {
            'admin': {'disabled': True},
            'logging': {'logs': {'default': {'level': 'DEBUG'}}},
            'apps': {
                'tls': {'certificates': {'load_files': [{'certificate': str(cert), 'key': str(key)}]}},
                'http': {'grace_period': '1s', 'servers': {'proxy': {
                    'listen': [f'127.0.0.1:{server_port}'],
                    'protocols': ['h1', 'h2', 'h3'],
                    'automatic_https': {'disable': True},
                    'tls_connection_policies': [{}],
                    'routes': [{'handle': [{
                        'handler': 'forward_proxy', 'udp': {},
                        'auth_credentials': [base64.b64encode(base64.b64encode(b'u:p')).decode()],
                        'acl': [{'allow': True, 'subjects': ['127.0.0.1', '::1']}],
                    }]}],
                }}},
            },
        }
        server_file = directory / 'caddy.json'
        server_file.write_text(json.dumps(server_config))
        client_config = {
            'listen': f'socks://127.0.0.1:{local_port}',
            'proxy': f'quic://u:p@localhost:{server_port}',
            'host-resolver-rules': 'MAP localhost 127.0.0.1',
            'trusted-cert': str(cert), 'masque-udp': True,
            'log': '',
        }
        client_file = directory / 'naive.json'
        client_file.write_text(json.dumps(client_config))
        with process([caddy, 'run', '--config', str(server_file)], directory, 'caddy.log') as server:
            wait_listen(server, server_port)
            with process([naive, str(client_file)], directory, 'naive.log') as client, tcp_echo_server() as tcp_port:
                wait_listen(client, local_port)
                verify_tcp(local_port, tcp_port)
                # Helpers perform a real SOCKS negotiation, then return the
                # control socket and relay endpoint.
                control, udp, relay = H.socks5_udp_associate(('127.0.0.1', local_port), 3)
                with control, udp:
                    udp.bind(('127.0.0.1', 0))
                    udp.settimeout(1)
                    with echo_server('127.0.0.1') as port:
                        for payload in [b'', b'hello', os.urandom(1000), os.urandom(1200)]:
                            exchange(udp, relay, '127.0.0.1', port, payload)
                        # Invalid FRAG/RSV are discarded without killing flow.
                        invalid = packet('127.0.0.1', port, b'fragment')
                        udp.sendto(invalid[:2] + b'\x01' + invalid[3:], relay)
                        # A single oversized packet must not reset the flow.
                        udp.sendto(packet('127.0.0.1', port, os.urandom(4000)), relay)
                        exchange(udp, relay, '127.0.0.1', port, b'after-oversized')
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as spoof:
                            spoof.settimeout(0.2)
                            spoof.sendto(packet('127.0.0.1', port, b'spoof'), relay)
                            try:
                                spoof.recvfrom(65536)
                                raise AssertionError('unexpected source port received a reply')
                            except socket.timeout:
                                pass
                        exchange(udp, relay, '127.0.0.1', port, b'after-spoof')
                    with echo_server('::1') as port6:
                        exchange(udp, relay, '::1', port6, b'ipv6')
                        exchange(udp, relay, 'localhost', port6, b'domain')
                # A separate association gets a separate socket and closes
                # independently from the first control connection.
                second, udp, second_relay = H.socks5_udp_associate(('127.0.0.1', local_port), 3)
                with second, udp:
                    udp.bind(('127.0.0.1', 0)); udp.settimeout(1)
                    with echo_server('127.0.0.1') as port:
                        exchange(udp, second_relay, '127.0.0.1', port, b'new-association')
                verify_tcp(local_port, tcp_port)
                time.sleep(0.2)
                if client.poll() is not None:
                    raise AssertionError('naive exited after association cleanup')
                print('PASS: TCP+padding coexistence/empty/IPv4/IPv6/domain/multiple associations/1200-byte payload/oversized recovery/source pinning')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
