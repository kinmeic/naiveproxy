#!/usr/bin/env python3
import argparse
import importlib.util
import ipaddress
from pathlib import Path
import secrets
import socket
import struct
import sys
import time


DEFAULT_SOCKS5 = "127.0.0.1:1080"
QUERY_NAME = "caddyserver.com"
DNS_PORT = 53
DNS_RESOLVERS = (
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
)


class DnsError(Exception):
    pass


def load_udp_test_helpers():
    helper_path = Path(__file__).with_name("run-udp-tests.py")
    spec = importlib.util.spec_from_file_location(
        "naiveproxy_run_udp_tests", helper_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load UDP test helpers from {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


udp_helpers = load_udp_test_helpers()


def encode_dns_name(name):
    labels = name.rstrip(".").split(".")
    encoded = bytearray()
    for label in labels:
        try:
            label_bytes = label.encode("idna")
        except UnicodeError as exc:
            raise DnsError(f"invalid DNS name {name!r}") from exc
        if not label_bytes or len(label_bytes) > 63:
            raise DnsError(f"invalid label in DNS name {name!r}")
        encoded.append(len(label_bytes))
        encoded.extend(label_bytes)
    encoded.append(0)
    if len(encoded) > 255:
        raise DnsError(f"DNS name is too long: {name!r}")
    return bytes(encoded)


def build_dns_query(name, transaction_id):
    # Standard recursive query for an IN A record.
    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        0x0100,
        1,
        0,
        0,
        0,
    )
    question = encode_dns_name(name) + struct.pack("!HH", 1, 1)
    return header + question


def read_dns_name(packet, offset):
    labels = []
    next_offset = None
    visited = set()

    while True:
        if offset >= len(packet):
            raise DnsError("truncated DNS name")
        if offset in visited:
            raise DnsError("DNS compression pointer loop")
        visited.add(offset)

        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise DnsError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer >= len(packet):
                raise DnsError("DNS compression pointer is out of range")
            if next_offset is None:
                next_offset = offset + 2
            offset = pointer
            continue
        if length & 0xC0:
            raise DnsError("invalid DNS label length")

        offset += 1
        if length == 0:
            if next_offset is None:
                next_offset = offset
            break
        if length > 63 or offset + length > len(packet):
            raise DnsError("truncated DNS label")
        try:
            labels.append(packet[offset:offset + length].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise DnsError("non-ASCII DNS label in response") from exc
        offset += length

    return ".".join(labels).lower(), next_offset


def parse_dns_response(packet, transaction_id, query_name):
    if len(packet) < 12:
        raise DnsError("DNS response is shorter than its header")

    response_id, flags, question_count, answer_count, _, _ = struct.unpack(
        "!HHHHHH", packet[:12]
    )
    if response_id != transaction_id:
        raise DnsError(
            f"transaction ID is 0x{response_id:04x}, expected "
            f"0x{transaction_id:04x}"
        )
    if not flags & 0x8000:
        raise DnsError("packet is not a DNS response")
    if flags & 0x7800:
        raise DnsError("DNS response has a non-zero opcode")
    if flags & 0x0200:
        raise DnsError("DNS response is truncated")
    rcode = flags & 0x000F
    if rcode != 0:
        raise DnsError(f"DNS server returned RCODE {rcode}")
    if question_count != 1:
        raise DnsError(
            f"DNS response has {question_count} questions instead of one"
        )

    offset = 12
    response_name, offset = read_dns_name(packet, offset)
    if offset + 4 > len(packet):
        raise DnsError("truncated DNS question")
    question_type, question_class = struct.unpack("!HH", packet[offset:offset + 4])
    offset += 4
    if response_name != query_name.rstrip(".").lower():
        raise DnsError(
            f"DNS response question is {response_name!r}, expected {query_name!r}"
        )
    if question_type != 1 or question_class != 1:
        raise DnsError("DNS response question is not an IN A query")

    addresses = []
    for _ in range(answer_count):
        _, offset = read_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise DnsError("truncated DNS answer header")
        record_type, record_class, _, data_length = struct.unpack(
            "!HHIH", packet[offset:offset + 10]
        )
        offset += 10
        if offset + data_length > len(packet):
            raise DnsError("truncated DNS answer data")
        if record_type == 1 and record_class == 1 and data_length == 4:
            addresses.append(str(ipaddress.ip_address(packet[offset:offset + 4])))
        offset += data_length

    if answer_count == 0:
        raise DnsError("DNS response contains no answers")
    if not addresses:
        raise DnsError("DNS response contains no IPv4 addresses")
    return addresses, answer_count


def new_transaction_id(used_ids):
    while True:
        transaction_id = secrets.randbelow(1 << 16)
        if transaction_id not in used_ids:
            return transaction_id


def run(args):
    tcp = None
    udp = None
    results = {}
    unexpected_packets = 0

    try:
        tcp, udp, relay = udp_helpers.socks5_udp_associate(
            args.socks5,
            args.timeout,
            args.username,
            args.password,
        )
        expected_relay = udp_helpers.normalized_endpoint(relay)
        print(f"SOCKS5 UDP relay: {relay[0]}:{relay[1]}")
        print(f"DNS query:        {QUERY_NAME} A")
        print()

        outstanding = {}
        used_ids = set()
        for resolver_name, resolver_host in DNS_RESOLVERS:
            transaction_id = new_transaction_id(used_ids)
            used_ids.add(transaction_id)
            query = build_dns_query(QUERY_NAME, transaction_id)
            target = (resolver_host, DNS_PORT)
            socks_packet = (
                b"\x00\x00\x00"
                + udp_helpers.encode_socks_address(*target)
                + query
            )
            sent_at = time.monotonic()
            udp.sendto(socks_packet, relay)
            outstanding[transaction_id] = {
                "name": resolver_name,
                "target": target,
                "sent_at": sent_at,
            }

        deadline = time.monotonic() + args.timeout
        while outstanding and time.monotonic() < deadline:
            udp.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                socks_packet, source = udp.recvfrom(65535)
            except socket.timeout:
                break

            source_endpoint = (source[0], source[1])
            if udp_helpers.normalized_endpoint(source_endpoint) != expected_relay:
                unexpected_packets += 1
                print(
                    f"Ignoring UDP packet from unexpected source {source_endpoint}",
                    file=sys.stderr,
                )
                continue

            try:
                destination, dns_packet = udp_helpers.parse_udp_packet(socks_packet)
            except udp_helpers.SocksError as exc:
                unexpected_packets += 1
                print(f"Ignoring malformed SOCKS5 UDP response: {exc}", file=sys.stderr)
                continue
            if len(dns_packet) < 2:
                unexpected_packets += 1
                print("Ignoring short DNS response", file=sys.stderr)
                continue

            transaction_id = struct.unpack("!H", dns_packet[:2])[0]
            request = outstanding.pop(transaction_id, None)
            if request is None:
                unexpected_packets += 1
                print(
                    f"Ignoring unexpected DNS transaction 0x{transaction_id:04x}",
                    file=sys.stderr,
                )
                continue

            elapsed = time.monotonic() - request["sent_at"]
            try:
                if (
                    udp_helpers.normalized_endpoint(destination)
                    != udp_helpers.normalized_endpoint(request["target"])
                ):
                    raise DnsError(
                        f"SOCKS5 destination is {destination}, expected "
                        f"{request['target']}"
                    )
                addresses, answer_count = parse_dns_response(
                    dns_packet,
                    transaction_id,
                    QUERY_NAME,
                )
            except DnsError as exc:
                results[request["name"]] = {
                    "ok": False,
                    "target": request["target"],
                    "error": str(exc),
                    "elapsed": elapsed,
                }
            else:
                results[request["name"]] = {
                    "ok": True,
                    "target": request["target"],
                    "addresses": addresses,
                    "answer_count": answer_count,
                    "elapsed": elapsed,
                }

        for request in outstanding.values():
            results[request["name"]] = {
                "ok": False,
                "target": request["target"],
                "error": f"timed out after {args.timeout:.2f}s",
            }
    finally:
        if udp is not None:
            udp.close()
        if tcp is not None:
            tcp.close()

    passed = 0
    for resolver_name, _ in DNS_RESOLVERS:
        result = results[resolver_name]
        target_host, target_port = result["target"]
        if result["ok"]:
            passed += 1
            addresses = ", ".join(result["addresses"])
            print(
                f"[PASS] {resolver_name:<10} {target_host}:{target_port}  "
                f"{result['elapsed'] * 1000:.2f} ms  "
                f"answers={result['answer_count']}  A={addresses}"
            )
        else:
            elapsed = (
                f"  {result['elapsed'] * 1000:.2f} ms"
                if "elapsed" in result
                else ""
            )
            print(
                f"[FAIL] {resolver_name:<10} {target_host}:{target_port}"
                f"{elapsed}  {result['error']}"
            )

    print()
    overall_ok = passed == len(DNS_RESOLVERS) and unexpected_packets == 0
    status = "PASS" if overall_ok else "FAIL"
    print(
        f"Result: {status} ({passed}/{len(DNS_RESOLVERS)} resolvers passed, "
        f"{unexpected_packets} unexpected packets)"
    )
    return 0 if overall_ok else 1


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Query caddyserver.com through SOCKS5 UDP using Cloudflare and "
            "Google DNS, then validate and report both responses."
        )
    )
    parser.add_argument(
        "socks5_address",
        nargs="?",
        help=f"SOCKS5 proxy as HOST:PORT. Default: {DEFAULT_SOCKS5}",
    )
    parser.add_argument(
        "--socks5",
        dest="socks5_option",
        help=f"SOCKS5 proxy as HOST:PORT. Default: {DEFAULT_SOCKS5}",
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
        "--timeout",
        type=udp_helpers.positive_float,
        default=5.0,
        help="maximum time to wait for both DNS responses. Default: 5",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.socks5_option and args.socks5_address:
        parser.error("use either positional SOCKS5_ADDRESS or --socks5, not both")
    if (args.username is None) != (args.password is None):
        parser.error("--username and --password must be used together")

    try:
        args.socks5 = udp_helpers.parse_host_port(
            args.socks5_option or args.socks5_address or DEFAULT_SOCKS5
        )
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    try:
        return run(args)
    except (OSError, DnsError, udp_helpers.SocksError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
