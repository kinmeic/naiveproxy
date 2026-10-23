#!/usr/bin/env python3
import argparse
import base64
import http.server
import os
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--naive', required=True)
parser.add_argument('--rootfs')
parser.add_argument('--target_cpu')
parser.add_argument('--server_protocol',
                    choices=['http', 'https'], default='https')
argv = parser.parse_args()

if argv.rootfs:
    try:
        os.remove(os.path.join(argv.rootfs, 'naive'))
    except OSError:
        pass

server_protocol = argv.server_protocol

_, certfile = tempfile.mkstemp()

result = subprocess.run(
    f'openssl req -new -x509 -keyout {certfile} -out {certfile} -days 1 -nodes -subj /C=XX'.split(), capture_output=True)
result.check_returncode()

HTTPS_SERVER_HOSTNAME = '127.0.0.1'
HTTP_SERVER_PORT = 60443 if server_protocol == 'https' else 60080

class TestHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/long-lived':
            return super().do_GET()

        # Stay active beyond the one-minute connection cleanup interval.
        chunks = [b'still-open\n'] * 14 + [b'long-lived-complete\n']
        self.send_response(200)
        self.send_header('Content-Length', str(sum(map(len, chunks))))
        self.end_headers()
        for i, chunk in enumerate(chunks):
            if i:
                time.sleep(5)
            try:
                self.wfile.write(chunk)
                self.wfile.flush()
            except OSError:
                return


httpd = http.server.HTTPServer(
    (HTTPS_SERVER_HOSTNAME, HTTP_SERVER_PORT), TestHTTPRequestHandler)
httpd.timeout = 1
httpd.allow_reuse_address = True
if server_protocol == 'https':
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=certfile)
    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

httpd_thread = threading.Thread(
    target=lambda httpd: httpd.serve_forever(), args=(httpd,), daemon=True)
httpd_thread.start()


def test_https_server(hostname, port, proxy=None, path='/404',
                      expected_output='Error code: 404', timeout=10):
    url = f'{server_protocol}://{hostname}:{port}{path}'
    cmdline = ['curl', '-k', '-s', '--max-time', str(timeout)]
    if proxy:
        cmdline.extend(['--proxy', proxy, '--noproxy', ''])
    cmdline.append(url)
    print('subprocess.run', ' '.join(cmdline))
    result = subprocess.run(cmdline, capture_output=True,
                            timeout=timeout + 5, text=True, encoding='utf-8')
    print(result.stderr, end='')
    return result.returncode == 0 and expected_output in result.stdout


assert test_https_server(HTTPS_SERVER_HOSTNAME,
                         HTTP_SERVER_PORT), 'https server not up'


def start_naive(naive_args, config_file):
    with_qemu = None
    if argv.target_cpu == 'arm64':
        with_qemu = 'aarch64'
    elif argv.target_cpu == 'arm':
        with_qemu = 'arm'
    elif argv.target_cpu == 'mipsel':
        with_qemu = 'mipsel'
    elif argv.target_cpu == 'mips64el':
        with_qemu = 'mips64el'
    elif argv.target_cpu == 'riscv64':
        with_qemu = 'riscv64'
    elif argv.target_cpu == 'loong64':
        with_qemu = 'loong64'

    if argv.rootfs:
        if not with_qemu:
            if not os.path.exists(os.path.join(argv.rootfs, 'naive')):
                shutil.copy2(argv.naive, argv.rootfs)
            # bwrap isolates filesystem, config_file needs a copy inside.
            if config_file is not None:
                shutil.copy2(config_file, argv.rootfs)
            cmdline = ['bwrap', '--die-with-parent', '--bind', argv.rootfs, '/',
                       '--proc', '/proc', '--dev', '/dev', '--chdir', '/', '/naive']
        else:
            cmdline = [f'qemu-{with_qemu}',
                       '-L', argv.rootfs, argv.naive]
    else:
        cmdline = [argv.naive]
    cmdline.extend(naive_args)

    env = os.environ.copy()
    env["TEST_MARK_STARTUP"] = "yes"
    proc = subprocess.Popen(cmdline, stdout=subprocess.DEVNULL, env=env,
                            stderr=subprocess.PIPE, text=True, encoding='utf-8')
    print('subprocess.Popen', ' '.join(cmdline), 'pid:', proc.pid)

    def terminate(proc):
        print('proc has timed out')
        print('terminate pid', proc.pid)
        proc.terminate()

    # Some qemu-user tests take a while to start.
    # See https://gitlab.com/qemu-project/qemu/-/issues/1729
    timeout = threading.Timer(20, terminate, args=(proc,))
    timeout.start()
    while True:
        if proc.poll() is not None:
            timeout.cancel()
            return proc.poll() == 0

        line = proc.stderr.readline().strip()
        print(line)
        if 'Failed to listen' in line:
            timeout.cancel()
            print('terminate pid', proc.pid)
            proc.terminate()
            return 'Failed to listen'
        elif 'TEST_MARK_STARTUP' in line:
            timeout.cancel()
            return proc


port = 10000


def allocate_port_number():
    global port
    port += 1
    if port > 60000:
        port = 10000
    return port


def test_naive_once(proxy, *args, **kwargs):
    port_map = {}

    class PortDict(dict):
        def __init__(self, port_map):
            self._port_map = port_map

        def __getitem__(self, key):
            if key.startswith('PORT'):
                if key not in self._port_map:
                    self._port_map[key] = str(allocate_port_number())
                return self._port_map[key]
            return key
    port_dict = PortDict(port_map)

    proxy = proxy.format_map(port_dict)

    config_file = kwargs.get('config_file')
    config_content = kwargs.get('config_content')
    if config_content is not None:
        config_content = config_content.format_map(port_dict)
        print(f"Writing {repr(config_content)} to {config_file}")
        with open(config_file, 'w') as f:
            f.write('{')
            f.write(config_content)
            f.write('}')

    naive_procs = []

    def cleanup():
        if config_file is not None:
            os.remove(config_file)
        for naive_proc in naive_procs:
            print('terminate pid', naive_proc.pid)
            naive_proc.terminate()

    for args_instance in args:
        naive_args = args_instance.format_map(port_dict).split()
        naive_proc = start_naive(naive_args, config_file)
        if naive_proc == 'Failed to listen':
            cleanup()
            return 'Failed to listen'
        if not naive_proc:
            cleanup()
            return False
        naive_procs.append(naive_proc)

    result = test_https_server(
        HTTPS_SERVER_HOSTNAME, HTTP_SERVER_PORT, proxy,
        path=kwargs.get('test_path', '/404'),
        expected_output=kwargs.get('expected_output', 'Error code: 404'),
        timeout=kwargs.get('test_timeout', 10))

    cleanup()

    return result


def test_naive(label, proxy, *args, **kwargs):
    RETRIES = 5
    result = None
    if argv.target_cpu == 'arm' and not label.startswith('Default'):
        # Arm tests are too slow in qemu-user
        # due to https://www.openwall.com/lists/musl/2017/06/15/9
        print('** SKIP TEST:', label, end='\n\n')
        return

    for i in range(RETRIES):
        result = test_naive_once(proxy, *args, **kwargs)
        if result == 'Failed to listen':
            result = False
            print('Retrying...')
            time.sleep(1)
            continue
        break
    if result is True:
        print('** TEST PASS:', label, end='\n\n')
    else:
        print('** TEST FAIL:', label, end='\n\n')
        sys.exit(1)


class BasicAuthProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_CONNECT(self):
        # Advance only on a match; a chain using the other chain's auth fails.
        expected = self.server.expected_credentials[0]
        encoded = base64.b64encode(expected.encode()).decode()
        if self.headers.get('Proxy-Authorization') != f'Basic {encoded}':
            self.connection.sendall(
                b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                b'Proxy-Authenticate: Basic realm="test"\r\n'
                b'Content-Length: 0\r\n'
                b'Connection: close\r\n\r\n')
            self.close_connection = True
            return

        host, port = self.path.rsplit(':', 1)
        try:
            upstream = socket.create_connection((host.strip('[]'), int(port)),
                                                timeout=10)
        except OSError:
            self.connection.sendall(
                b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n'
                b'Connection: close\r\n\r\n')
            self.close_connection = True
            return

        self.server.expected_credentials.pop(0)
        self.connection.sendall(
            b'HTTP/1.1 200 Connection Established\r\n\r\n')
        sockets = (self.connection, upstream)
        try:
            while True:
                readable, _, exceptional = select.select(
                    sockets, [], sockets, 30)
                if exceptional or not readable:
                    return
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = (upstream if source is self.connection
                                   else self.connection)
                    destination.sendall(data)
        except OSError:
            return
        finally:
            upstream.close()

    def log_message(self, format, *args):
        pass


def test_naive_auth_isolation():
    listen_a = allocate_port_number()
    listen_b = allocate_port_number()
    credentials = ['tenant-a:pass-a', 'tenant-b:pass-b']

    auth_server = http.server.ThreadingHTTPServer(
        ('127.0.0.1', 0), BasicAuthProxyHandler)
    auth_port = auth_server.server_address[1]
    auth_server.expected_credentials = credentials.copy()
    auth_thread = threading.Thread(
        target=auth_server.serve_forever, daemon=True)
    auth_thread.start()

    naive_args = [
        '--log',
        f'--listen=socks://127.0.0.1:{listen_a}',
        f'--listen=socks://127.0.0.1:{listen_b}',
        f'--proxy=http://tenant-a:pass-a@127.0.0.1:{auth_port}',
        f'--proxy=http://tenant-b:pass-b@127.0.0.1:{auth_port}',
    ]
    proc = None
    try:
        proc = start_naive(naive_args, None)
        if not isinstance(proc, subprocess.Popen):
            raise RuntimeError('Failed to start NaiveProxy for auth test')
        result_a = test_https_server(
            HTTPS_SERVER_HOSTNAME, HTTP_SERVER_PORT,
            f'socks5h://127.0.0.1:{listen_a}')
        result_b = test_https_server(
            HTTPS_SERVER_HOSTNAME, HTTP_SERVER_PORT,
            f'socks5h://127.0.0.1:{listen_b}')
    finally:
        if isinstance(proc, subprocess.Popen) and proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        auth_server.shutdown()
        auth_server.server_close()
        auth_thread.join(timeout=10)

    if result_a and result_b and not auth_server.expected_credentials:
        print('** TEST PASS: Multiple proxy chains isolate auth', end='\n\n')
    else:
        print('** TEST FAIL: Multiple proxy chains isolate auth', end='\n\n')
        sys.exit(1)


test_naive('Default config', 'socks5h://127.0.0.1:1080',
           '--log')

test_naive('Default config file', 'socks5h://127.0.0.1:{PORT1}',
           '',
           config_content='"listen":"socks://127.0.0.1:{PORT1}","log":""',
           config_file='config.json')

test_naive('Custom config file', 'socks5h://127.0.0.1:{PORT1}',
           'custom.json',
           config_content='"listen":"socks://127.0.0.1:{PORT1}","log":""',
           config_file='custom.json')

test_naive('Multiple listens - command line', 'socks5h://127.0.0.1:{PORT1}',
           '--log --listen=socks://:{PORT1} --listen=http://:{PORT2}')

test_naive('Multiple listens - command line', 'http://127.0.0.1:{PORT2}',
           '--log --listen=socks://:{PORT1} --listen=http://:{PORT2}')

test_naive('Multiple listens - config file', 'socks5h://127.0.0.1:{PORT1}',
           'multiple-listen.json',
           config_content='"listen":["socks://:{PORT1}", "http://:{PORT2}"],"log":""',
           config_file='multiple-listen.json')

test_naive('Multiple listens - config file', 'http://127.0.0.1:{PORT2}',
           'multiple-listen.json',
           config_content='"listen":["socks://:{PORT1}", "http://:{PORT2}"],"log":""',
           config_file='multiple-listen.json')

test_naive('Multiple proxies - command line', 'socks5h://127.0.0.1:{PORT1}',
           '--log --listen=socks://:{PORT1} --listen=socks://:{PORT2} --proxy=http://127.0.0.1:{PORT3} --proxy=http://127.0.0.1:{PORT4}',
           '--log --listen=http://:{PORT3} --listen=http://:{PORT4} --proxy=socks://127.0.0.1:{PORT5}',
           '--log --listen=socks://:{PORT5}')

test_naive('Multiple proxies - command line', 'socks5h://127.0.0.1:{PORT2}',
           '--log --listen=socks://:{PORT1} --listen=socks://:{PORT2} --proxy=http://127.0.0.1:{PORT3} --proxy=http://127.0.0.1:{PORT4}',
           '--log --listen=http://:{PORT3} --listen=http://:{PORT4} --proxy=socks://127.0.0.1:{PORT5}',
           '--log --listen=socks://:{PORT5}')

test_naive('Trivial - listen scheme only', 'socks5h://127.0.0.1:1080',
           '--log --listen=socks://')

test_naive('Trivial - listen no host', 'socks5h://127.0.0.1:{PORT1}',
           '--log --listen=socks://:{PORT1}')

test_naive('Trivial - listen no port', 'socks5h://127.0.0.1:1080',
           '--log --listen=socks://127.0.0.1')

test_naive('Trivial - auth', 'socks5h://user:pass@127.0.0.1:{PORT1}',
           '--log --listen=socks://user:pass@127.0.0.1:{PORT1}')

test_naive('Trivial - auth with special chars', 'socks5h://user:^@127.0.0.1:{PORT1}',
           '--log --listen=socks://user:^@127.0.0.1:{PORT1}')

test_naive('Trivial - auth with special chars', 'socks5h://^:^@127.0.0.1:{PORT1}',
           '--log --listen=socks://^:^@127.0.0.1:{PORT1}')

test_naive('Trivial - auth with empty pass', 'socks5h://user:@127.0.0.1:{PORT1}',
           '--log --listen=socks://user:@127.0.0.1:{PORT1}')

test_naive('SOCKS-SOCKS', 'socks5h://127.0.0.1:{PORT1}',
           '--log --listen=socks://:{PORT1} --proxy=socks://127.0.0.1:{PORT2}',
           '--log --listen=socks://:{PORT2}')

test_naive('SOCKS-SOCKS - proxy no port', 'socks5h://127.0.0.1:{PORT1}',
           '--log --listen=socks://:{PORT1} --proxy=socks://127.0.0.1',
           '--log --listen=socks://:1080')

test_naive('SOCKS-HTTP', 'socks5h://127.0.0.1:{PORT1}',
           '--log --listen=socks://:{PORT1} --proxy=http://127.0.0.1:{PORT2}',
           '--log --listen=http://:{PORT2}')

test_naive('HTTP-HTTP', 'http://127.0.0.1:{PORT1}',
           '--log --listen=http://:{PORT1} --proxy=http://127.0.0.1:{PORT2}',
           '--log --listen=http://:{PORT2}')

test_naive('HTTP-SOCKS', 'http://127.0.0.1:{PORT1}',
           '--log --listen=http://:{PORT1} --proxy=socks://127.0.0.1:{PORT2}',
           '--log --listen=socks://:{PORT2}')

test_naive('SOCKS-SOCKS-SOCKS', 'socks5h://127.0.0.1:{PORT1}',
           '--log --listen=socks://:{PORT1} --proxy=socks://127.0.0.1:{PORT2}',
           '--log --listen=socks://:{PORT2} --proxy=socks://127.0.0.1:{PORT3}',
           '--log --listen=socks://:{PORT3}')

test_naive('SOCKS-HTTP-SOCKS', 'socks5h://127.0.0.1:{PORT1}',
           '--log --listen=socks://:{PORT1} --proxy=http://127.0.0.1:{PORT2}',
           '--log --listen=http://:{PORT2} --proxy=socks://127.0.0.1:{PORT3}',
           '--log --listen=socks://:{PORT3}')

test_naive('HTTP-SOCKS-HTTP', 'http://127.0.0.1:{PORT1}',
           '--log --listen=http://:{PORT1} --proxy=socks://127.0.0.1:{PORT2}',
           '--log --listen=socks://:{PORT2} --proxy=http://127.0.0.1:{PORT3}',
           '--log --listen=http://:{PORT3}')

test_naive('HTTP-HTTP-HTTP', 'http://127.0.0.1:{PORT1}',
           '--log --listen=http://:{PORT1} --proxy=http://127.0.0.1:{PORT2}',
           '--log --listen=http://:{PORT2} --proxy=http://127.0.0.1:{PORT3}',
           '--log --listen=http://:{PORT3}')

test_naive('HTTP-HTTP (with auth)', 'http://127.0.0.1:{PORT1}',
           '--log --listen=http://:{PORT1} --proxy=http://hello:world@127.0.0.1:{PORT2}',
           '--log --listen=http://hello:world@127.0.0.1:{PORT2}')

test_naive('HTTPa-HTTPb,HTTPc (chaining with remote loop)', 'http://127.0.0.1:{PORT1}',
           '--log --listen=http://:{PORT2}',
           '--log --listen=http://:{PORT1} --proxy=http://127.0.0.1:{PORT2},http://127.0.0.1:{PORT2}')

test_naive('HTTPa-HTTPb,HTTPc (chaining with multiple auth)', 'http://127.0.0.1:{PORT1}',
           '--log --listen=http://hello:world2@127.0.0.1:{PORT2}',
           '--log --listen=http://hello:world3@127.0.0.1:{PORT3}',
           '--log --listen=http://127.0.0.1:{PORT1} --proxy=http://hello:world2@127.0.0.1:{PORT2},http://hello:world3@127.0.0.1:{PORT3}')

test_naive_auth_isolation()

if server_protocol == 'https':
    test_naive(
        'Long-lived connection survives tunnel cleanup',
        'socks5h://127.0.0.1:{PORT1}',
        '--log --listen=socks://127.0.0.1:{PORT1} '
        '--idle-timeout=30 --tunnel-timeout=1',
        test_path='/long-lived',
        expected_output='long-lived-complete',
        test_timeout=100)
