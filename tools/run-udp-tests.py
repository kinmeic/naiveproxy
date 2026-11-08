#!/usr/bin/env python3
import argparse
import datetime
import ipaddress
import socket
import statistics
import struct
import sys
import time


DEFAULT_SOCKS5 = "127.0.0.1:1080"
DEFAULT_TARGET = "127.0.0.1:12345"


class SocksError(Exception):
    pass


def parse_host_port(value, default_port=None):
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
    elif value.startswith("[") and "]:" in value:
        host, port = value[1:].rsplit("]:", 1)
    elif default_port is not None:
        host = value
        port = default_port
    else:
        raise argparse.ArgumentTypeError(
            f"expected HOST:PORT, got {value!r}"
        )

    if not host:
        raise argparse.ArgumentTypeError("host must not be empty")

    try:
        port = int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid port in {value!r}") from exc

    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError(f"port out of range in {value!r}")

    return host, port


def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise SocksError("SOCKS5 server closed the TCP control connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def encode_socks_address(host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        host_bytes = host.encode("idna")
        if len(host_bytes) > 255:
            raise SocksError(f"domain name is too long: {host!r}")
        return b"\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", port)

    if ip.version == 4:
        return b"\x01" + ip.packed + struct.pack("!H", port)
    return b"\x04" + ip.packed + struct.pack("!H", port)


def decode_socks_address(sock, atyp):
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(sock, 4))
    elif atyp == 3:
        length = recv_exact(sock, 1)[0]
        if length == 0:
            raise SocksError("SOCKS5 server returned an empty domain name")
        try:
            host = recv_exact(sock, length).decode("idna")
        except UnicodeError as exc:
            raise SocksError("SOCKS5 server returned an invalid domain name") from exc
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise SocksError(f"SOCKS5 server returned unsupported address type {atyp}")

    port = struct.unpack("!H", recv_exact(sock, 2))[0]
    return host, port


def parse_udp_packet(packet):
    if len(packet) < 4:
        raise SocksError("received a short SOCKS5 UDP packet")
    if packet[0:2] != b"\x00\x00":
        raise SocksError("received a SOCKS5 UDP packet with non-zero reserved bytes")
    if packet[2] != 0:
        raise SocksError("fragmented SOCKS5 UDP packets are not supported")

    offset = 3
    atyp = packet[offset]
    offset += 1
    if atyp == 1:
        addr_len = 4
        if len(packet) < offset + addr_len + 2:
            raise SocksError("received a short SOCKS5 UDP IPv4 packet")
        host = socket.inet_ntop(
            socket.AF_INET, packet[offset:offset + addr_len]
        )
    elif atyp == 3:
        if len(packet) < offset + 1:
            raise SocksError("received a short SOCKS5 UDP domain packet")
        addr_len = packet[offset]
        if addr_len == 0:
            raise SocksError("received an empty SOCKS5 UDP domain name")
        offset += 1
        if len(packet) < offset + addr_len + 2:
            raise SocksError("received a short SOCKS5 UDP domain packet")
        try:
            host = packet[offset:offset + addr_len].decode("idna")
        except UnicodeError as exc:
            raise SocksError(
                "received an invalid SOCKS5 UDP domain name"
            ) from exc
    elif atyp == 4:
        addr_len = 16
        if len(packet) < offset + addr_len + 2:
            raise SocksError("received a short SOCKS5 UDP IPv6 packet")
        host = socket.inet_ntop(
            socket.AF_INET6, packet[offset:offset + addr_len]
        )
    else:
        raise SocksError(f"received unsupported SOCKS5 UDP address type {atyp}")

    offset += addr_len
    port = struct.unpack("!H", packet[offset:offset + 2])[0]
    return (host, port), packet[offset + 2:]


def socks5_udp_associate(proxy, timeout, username=None, password=None):
    tcp = socket.create_connection(proxy, timeout=timeout)
    tcp.settimeout(timeout)

    methods = b"\x00" if username is None else b"\x00\x02"
    tcp.sendall(b"\x05" + bytes([len(methods)]) + methods)
    response = recv_exact(tcp, 2)
    if response[0] != 5:
        raise SocksError("SOCKS5 server returned an invalid version")
    if response[1] == 2 and username is not None:
        username_bytes = username.encode()
        password_bytes = password.encode()
        if len(username_bytes) > 255:
            raise SocksError("SOCKS5 username must encode to at most 255 bytes")
        if len(password_bytes) > 255:
            raise SocksError("SOCKS5 password must encode to at most 255 bytes")
        tcp.sendall(
            b"\x01"
            + bytes([len(username_bytes)])
            + username_bytes
            + bytes([len(password_bytes)])
            + password_bytes
        )
        auth_response = recv_exact(tcp, 2)
        if auth_response[0] != 1 or auth_response[1] != 0:
            raise SocksError("SOCKS5 username/password authentication failed")
    elif response[1] != 0:
        raise SocksError(
            f"SOCKS5 server selected unsupported authentication method {response[1]}"
        )

    tcp.sendall(b"\x05\x03\x00" + encode_socks_address("0.0.0.0", 0))
    header = recv_exact(tcp, 4)
    if header[0] != 5:
        raise SocksError("SOCKS5 server returned an invalid reply version")
    if header[1] != 0:
        raise SocksError(f"SOCKS5 UDP ASSOCIATE failed with reply code {header[1]}")
    if header[2] != 0:
        raise SocksError("SOCKS5 server returned an invalid reserved byte")

    relay_host, relay_port = decode_socks_address(tcp, header[3])
    if relay_port == 0:
        raise SocksError("SOCKS5 server returned UDP relay port zero")
    if relay_host in ("0.0.0.0", "::"):
        relay_host = proxy[0]

    udp = socket.socket(socket.AF_INET6 if ":" in relay_host else socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout)
    return tcp, udp, (relay_host, relay_port)


def build_payload(sequence):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        f"Datagram test {sequence}: {now.isoformat(timespec='microseconds')}"
    ).encode()


def normalized_endpoint(endpoint):
    host, port = endpoint
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode("idna").lower()
    return host, port


def print_report(args, stats, elapsed):
    sent = stats["sent"]
    received = stats["received"]
    matched = stats["matched"]
    lost = sent - matched
    loss_rate = (lost / sent * 100.0) if sent else 0.0

    print()
    print("UDP test report")
    print(f"  SOCKS5 proxy: {args.socks5[0]}:{args.socks5[1]}")
    print(f"  Echo target:  {args.target[0]}:{args.target[1]}")
    print(f"  Test elapsed: {elapsed:.2f}s ({args.duration:.2f}s configured)")
    print(f"  Sent:         {sent}")
    print(f"  Received:     {received}")
    print(f"  Matched:      {matched}")
    print(f"  Mismatched:   {stats['mismatched']}")
    print(f"  Timeouts:     {stats['timeouts']}")
    print(f"  Errors:       {stats['errors']}")
    print(f"  Loss:         {lost} ({loss_rate:.1f}%)")

    if stats["rtts"]:
        print(
            "  RTT:          "
            f"min {min(stats['rtts']) * 1000:.2f} ms, "
            f"avg {statistics.mean(stats['rtts']) * 1000:.2f} ms, "
            f"max {max(stats['rtts']) * 1000:.2f} ms"
        )


def run(args):
    tcp = None
    udp = None
    stats = {
        "sent": 0,
        "received": 0,
        "matched": 0,
        "mismatched": 0,
        "timeouts": 0,
        "errors": 0,
        "rtts": [],
    }
    test_started_at = None

    try:
        tcp, udp, relay = socks5_udp_associate(
            args.socks5, args.timeout, args.username, args.password
        )
        print(
            f"Using SOCKS5 UDP relay {relay[0]}:{relay[1]} "
            f"for echo target {args.target[0]}:{args.target[1]}"
        )

        target_header = b"\x00\x00\x00" + encode_socks_address(*args.target)
        expected_target = normalized_endpoint(args.target)
        expected_relay = normalized_endpoint(relay)
        outstanding = {}
        sequence = 0
        test_started_at = time.monotonic()
        end = test_started_at + args.duration
        while time.monotonic() < end:
            payload = build_payload(sequence)
            sequence += 1
            sent_at = time.monotonic()
            udp.sendto(target_header + payload, relay)
            stats["sent"] += 1
            outstanding[payload] = sent_at

            try:
                # Give every datagram counted as sent the full configured
                # receive window. Capping this at the remaining test duration
                # makes the final packet report a false timeout whenever it is
                # sent less than one RTT before the deadline.
                udp.settimeout(args.timeout)
                packet, source = udp.recvfrom(65535)
                stats["received"] += 1
                source_endpoint = (source[0], source[1])
                destination, echoed = parse_udp_packet(packet)
                original_sent_at = outstanding.pop(echoed, None)
                if (
                    normalized_endpoint(source_endpoint) == expected_relay
                    and normalized_endpoint(destination) == expected_target
                    and original_sent_at is not None
                ):
                    stats["matched"] += 1
                    stats["rtts"].append(time.monotonic() - original_sent_at)
                else:
                    stats["mismatched"] += 1
                    print(
                        "Mismatched response: "
                        f"source={source_endpoint!r} expected_relay={relay!r}, "
                        f"destination={destination!r} "
                        f"expected_target={args.target!r}, "
                        f"payload_was_outstanding={original_sent_at is not None}",
                        file=sys.stderr,
                    )
            except socket.timeout:
                stats["timeouts"] += 1
            except OSError as exc:
                stats["errors"] += 1
                print(f"Receive failed: {exc}", file=sys.stderr)

            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(args.interval, remaining))
    finally:
        elapsed = (
            time.monotonic() - test_started_at
            if test_started_at is not None
            else 0.0
        )
        if udp is not None:
            udp.close()
        if tcp is not None:
            tcp.close()
        print_report(args, stats, elapsed)

    return 0 if stats["sent"] == stats["matched"] and stats["errors"] == 0 else 1


def positive_float(value):
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a positive number, got {value!r}") from exc
    if result <= 0:
        raise argparse.ArgumentTypeError(f"expected a positive number, got {value!r}")
    return result


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Send UDP datagrams through a SOCKS5 proxy to an echo server and "
            "report delivery and RTT statistics."
        ),
        epilog=(
            "Example echo server:\n"
            "  socat -v UDP-LISTEN:12345,reuseaddr,fork EXEC:/bin/cat\n\n"
            "Example test:\n"
            "  tools/run-udp-tests.py --socks5 127.0.0.1:1080 "
            "--target 127.0.0.1:12345 --duration 30"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "socks5_address",
        nargs="?",
        help=f"SOCKS5 proxy address as HOST:PORT. Default: {DEFAULT_SOCKS5}",
    )
    parser.add_argument(
        "--socks5",
        dest="socks5_option",
        help=f"SOCKS5 proxy address as HOST:PORT. Default: {DEFAULT_SOCKS5}",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"UDP echo target address as HOST:PORT. Default: {DEFAULT_TARGET}",
    )
    parser.add_argument(
        "--username",
        help="SOCKS5 username. Must be used together with --password.",
    )
    parser.add_argument(
        "--password",
        help="SOCKS5 password. Must be used together with --username.",
    )
    parser.add_argument(
        "--duration",
        type=positive_float,
        default=10.0,
        help="test duration in seconds. Default: 10",
    )
    parser.add_argument(
        "--interval",
        type=positive_float,
        default=1.0,
        help="delay between datagrams in seconds. Default: 1",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=2.0,
        help="per-operation timeout in seconds. Default: 2",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.socks5_option and args.socks5_address:
        parser.error("use either positional SOCKS5_ADDRESS or --socks5, not both")
    if (args.username is None) != (args.password is None):
        parser.error("--username and --password must be used together")

    args.socks5 = parse_host_port(args.socks5_option or args.socks5_address or DEFAULT_SOCKS5)
    args.target = parse_host_port(args.target)

    try:
        return run(args)
    except (OSError, SocksError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
