#!/usr/bin/env python3
"""Minimal TURN protocol probe for ACL/security testing.

Supports:
- unauthenticated Allocate checks
- authenticated Allocate + CreatePermission checks (including ::ffff: IPv4-mapped IPv6 peers)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass

MAGIC = 0x2112A442
HDR_LEN = 20

# Methods
ALLOCATE_REQ = 0x0003
ALLOCATE_OK = 0x0103
ALLOCATE_ERR = 0x0113
CREATE_PERMISSION_REQ = 0x0008
CREATE_PERMISSION_OK = 0x0108
CREATE_PERMISSION_ERR = 0x0118

# Attributes
A_USERNAME = 0x0006
A_MESSAGE_INTEGRITY = 0x0008
A_ERROR_CODE = 0x0009
A_LIFETIME = 0x000D
A_XOR_PEER_ADDRESS = 0x0012
A_REALM = 0x0014
A_NONCE = 0x0015
A_REQUESTED_TRANSPORT = 0x0019
A_REQUESTED_ADDRESS_FAMILY = 0x0017

# Address families for STUN attrs
FAM_V4 = 0x01
FAM_V6 = 0x02


class ProbeError(RuntimeError):
    pass


@dataclass
class TurnAuth:
    username: str
    password: str
    realm: bytes | None = None
    nonce: bytes | None = None

    @property
    def key(self) -> bytes:
        if self.realm is None:
            raise ProbeError("realm is not set")
        realm_str = self.realm.decode("utf-8", errors="replace")
        return hashlib.md5(f"{self.username}:{realm_str}:{self.password}".encode("utf-8")).digest()


def txid() -> bytes:
    return os.urandom(12)


def stun_header(method: int, length: int, tid: bytes) -> bytes:
    return struct.pack("!HHI", method, length, MAGIC) + tid


def stun_attr(attr_type: int, value: bytes) -> bytes:
    pad = (4 - (len(value) % 4)) % 4
    return struct.pack("!HH", attr_type, len(value)) + value + (b"\x00" * pad)


def parse_stun(data: bytes) -> tuple[int, dict[int, bytes]]:
    if len(data) < HDR_LEN:
        raise ProbeError("short STUN response")
    method, length = struct.unpack("!HH", data[:4])
    if len(data) < HDR_LEN + length:
        raise ProbeError("truncated STUN response")
    attrs: dict[int, bytes] = {}
    off = HDR_LEN
    end = HDR_LEN + length
    while off + 4 <= end:
        atype, alen = struct.unpack("!HH", data[off : off + 4])
        start = off + 4
        finish = start + alen
        attrs[atype] = data[start:finish]
        off = off + 4 + ((alen + 3) & ~3)
    return method, attrs


def error_code(attrs: dict[int, bytes]) -> int:
    raw = attrs.get(A_ERROR_CODE, b"")
    if len(raw) < 4:
        return 0
    return raw[2] * 100 + raw[3]


def add_message_integrity(packet_without_mi: bytes, key: bytes) -> bytes:
    # MI attribute is always 24 bytes total (type+len+20-byte SHA1)
    mutable = bytearray(packet_without_mi)
    cur_len = struct.unpack("!H", mutable[2:4])[0]
    struct.pack_into("!H", mutable, 2, cur_len + 24)
    digest = hmac.new(key, bytes(mutable), hashlib.sha1).digest()
    return packet_without_mi + stun_attr(A_MESSAGE_INTEGRITY, digest)


def build_request(method: int, tid: bytes, attrs: list[tuple[int, bytes]], auth: TurnAuth | None = None) -> bytes:
    body = b"".join(stun_attr(a, v) for (a, v) in attrs)

    if auth is not None:
        if auth.realm is None or auth.nonce is None:
            raise ProbeError("auth requested but realm/nonce missing")
        body += stun_attr(A_USERNAME, auth.username.encode("utf-8"))
        body += stun_attr(A_REALM, auth.realm)
        body += stun_attr(A_NONCE, auth.nonce)

    packet = stun_header(method, len(body), tid) + body

    if auth is not None:
        packet = add_message_integrity(packet, auth.key)

    return packet


def xor_peer_value(ip: ipaddress._BaseAddress, port: int, tid: bytes) -> bytes:
    xport = port ^ (MAGIC >> 16)
    if ip.version == 4:
        raw = ip.packed
        xip = bytes(b ^ k for (b, k) in zip(raw, struct.pack("!I", MAGIC)))
        return struct.pack("!BBH", 0, FAM_V4, xport) + xip

    raw = ip.packed
    key = struct.pack("!I", MAGIC) + tid
    xip = bytes(b ^ k for (b, k) in zip(raw, key))
    return struct.pack("!BBH", 0, FAM_V6, xport) + xip


def make_socket(host: str, port: int, timeout: float) -> socket.socket:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    if not infos:
        raise ProbeError(f"could not resolve host {host}")
    # Prefer IPv4 first in dual-stack environments for consistent behavior
    # with common coturn deployments and host-published Docker ports.
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    last_error: OSError | None = None
    for af, stype, proto, _, sockaddr in infos:
        try:
            s = socket.socket(af, stype, proto)
            s.settimeout(timeout)
            s.connect(sockaddr)
            return s
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise ProbeError(f"could not open UDP socket to {host}:{port}")


def send_recv(sock: socket.socket, packet: bytes) -> bytes:
    sock.send(packet)
    return sock.recv(8192)


def request_nonce_realm(sock: socket.socket, alloc_family: str | None = None) -> TurnAuth:
    attrs: list[tuple[int, bytes]] = [
        (A_REQUESTED_TRANSPORT, struct.pack("!I", 17 << 24)),  # UDP
    ]
    if alloc_family == "ipv4":
        attrs.append((A_REQUESTED_ADDRESS_FAMILY, struct.pack("!I", FAM_V4 << 24)))
    elif alloc_family == "ipv6":
        attrs.append((A_REQUESTED_ADDRESS_FAMILY, struct.pack("!I", FAM_V6 << 24)))

    pkt = build_request(ALLOCATE_REQ, txid(), attrs, auth=None)
    method, attrs = parse_stun(send_recv(sock, pkt))

    if method != ALLOCATE_ERR:
        raise ProbeError(f"expected ALLOCATE error challenge, got method=0x{method:04x}")
    if A_REALM not in attrs or A_NONCE not in attrs:
        raise ProbeError("ALLOCATE challenge missing REALM/NONCE")

    return TurnAuth(username="", password="", realm=attrs[A_REALM], nonce=attrs[A_NONCE])


def allocate_with_auth(sock: socket.socket, auth: TurnAuth, alloc_family: str) -> tuple[int, dict[int, bytes]]:
    fam_attr = FAM_V4 if alloc_family == "ipv4" else FAM_V6

    for _ in range(3):
        attrs = [
            (A_REQUESTED_TRANSPORT, struct.pack("!I", 17 << 24)),
            (A_REQUESTED_ADDRESS_FAMILY, struct.pack("!I", fam_attr << 24)),
        ]
        pkt = build_request(ALLOCATE_REQ, txid(), attrs, auth=auth)
        method, parsed = parse_stun(send_recv(sock, pkt))

        if method == ALLOCATE_OK:
            return method, parsed

        if method == ALLOCATE_ERR and error_code(parsed) == 438 and A_NONCE in parsed:
            auth.nonce = parsed[A_NONCE]
            if A_REALM in parsed:
                auth.realm = parsed[A_REALM]
            continue

        return method, parsed

    return ALLOCATE_ERR, {}


def create_permission_with_auth(
    sock: socket.socket,
    auth: TurnAuth,
    peer_ip: ipaddress._BaseAddress,
    peer_port: int,
) -> tuple[int, dict[int, bytes]]:
    for _ in range(3):
        tid = txid()
        attrs = [(A_XOR_PEER_ADDRESS, xor_peer_value(peer_ip, peer_port, tid))]
        pkt = build_request(CREATE_PERMISSION_REQ, tid, attrs, auth=auth)
        method, parsed = parse_stun(send_recv(sock, pkt))

        if method == CREATE_PERMISSION_OK:
            return method, parsed

        if method == CREATE_PERMISSION_ERR and error_code(parsed) == 438 and A_NONCE in parsed:
            auth.nonce = parsed[A_NONCE]
            if A_REALM in parsed:
                auth.realm = parsed[A_REALM]
            continue

        return method, parsed

    return CREATE_PERMISSION_ERR, {}


def mode_unauth_allocate(args: argparse.Namespace) -> int:
    sock = make_socket(args.host, args.port, args.timeout)
    try:
        attrs = [(A_REQUESTED_TRANSPORT, struct.pack("!I", 17 << 24))]
        pkt = build_request(ALLOCATE_REQ, txid(), attrs, auth=None)
        method, parsed = parse_stun(send_recv(sock, pkt))
    finally:
        sock.close()

    denied = method == ALLOCATE_ERR
    verdict_ok = (args.expect == "deny" and denied) or (args.expect == "allow" and method == ALLOCATE_OK)

    code = error_code(parsed) if method == ALLOCATE_ERR else 0
    outcome = "deny" if denied else "allow"
    print(
        f"RESULT mode=unauth-allocate host={args.host}:{args.port} "
        f"outcome={outcome} code={code or 'none'} expected={args.expect} "
        f"verdict={'pass' if verdict_ok else 'fail'}"
    )
    return 0 if verdict_ok else 1


def mode_create_permission(args: argparse.Namespace) -> int:
    peer = ipaddress.ip_address(args.peer)

    # If allocation family is not explicitly set, choose based on peer address family.
    if args.allocation_family:
        alloc_family = args.allocation_family
    else:
        alloc_family = "ipv6" if peer.version == 6 else "ipv4"

    auth = TurnAuth(username=args.username, password=args.password)

    sock = make_socket(args.host, args.port, args.timeout)
    try:
        challenge = request_nonce_realm(sock, alloc_family)
        auth.realm = challenge.realm
        auth.nonce = challenge.nonce

        alloc_method, alloc_attrs = allocate_with_auth(sock, auth, alloc_family)
        if alloc_method != ALLOCATE_OK:
            code = error_code(alloc_attrs) if alloc_method == ALLOCATE_ERR else 0
            print(
                f"RESULT mode=create-permission peer={args.peer} alloc_family={alloc_family} "
                f"step=allocate outcome=error code={code or 'none'} expected={args.expect} verdict=fail"
            )
            return 1

        perm_method, perm_attrs = create_permission_with_auth(sock, auth, peer, args.peer_port)
    finally:
        sock.close()

    allowed = perm_method == CREATE_PERMISSION_OK
    denied = perm_method == CREATE_PERMISSION_ERR

    if args.expect == "allow":
        verdict_ok = allowed
    else:
        verdict_ok = denied

    code = error_code(perm_attrs) if denied else 0
    outcome = "allow" if allowed else "deny" if denied else f"method-0x{perm_method:04x}"
    print(
        f"RESULT mode=create-permission peer={args.peer}:{args.peer_port} alloc_family={alloc_family} "
        f"outcome={outcome} code={code or 'none'} expected={args.expect} verdict={'pass' if verdict_ok else 'fail'}"
    )
    return 0 if verdict_ok else 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="TURN ACL probe")
    sub = p.add_subparsers(dest="mode", required=True)

    p_ua = sub.add_parser("unauth-allocate", help="Check unauthenticated ALLOCATE behavior")
    p_ua.add_argument("--host", required=True)
    p_ua.add_argument("--port", type=int, default=3478)
    p_ua.add_argument("--expect", choices=["allow", "deny"], default="deny")
    p_ua.add_argument("--timeout", type=float, default=3.0)
    p_ua.set_defaults(func=mode_unauth_allocate)

    p_cp = sub.add_parser("create-permission", help="Check authenticated CreatePermission behavior")
    p_cp.add_argument("--host", required=True)
    p_cp.add_argument("--port", type=int, default=3478)
    p_cp.add_argument("--username", required=True)
    p_cp.add_argument("--password", required=True)
    p_cp.add_argument("--peer", required=True)
    p_cp.add_argument("--peer-port", type=int, default=80)
    p_cp.add_argument("--expect", choices=["allow", "deny"], required=True)
    p_cp.add_argument("--allocation-family", choices=["ipv4", "ipv6"])
    p_cp.add_argument("--timeout", type=float, default=3.0)
    p_cp.set_defaults(func=mode_create_permission)

    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        return args.func(args)
    except (ProbeError, OSError, socket.timeout) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
