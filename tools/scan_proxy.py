#!/usr/bin/env python3
"""MIT: scan-only local proxy for ClamAV INSTREAM; Unix credentials or mutual TLS."""
import argparse
import concurrent.futures
import json
import os
import socket
import ssl
import stat
import struct
import threading
import time


def exact(sock, length, deadline):
    chunks = []
    while length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('deadline exceeded')
        sock.settimeout(remaining)
        data = sock.recv(length)
        if not data:
            raise ValueError('truncated stream')
        chunks.append(data)
        length -= len(data)
    return b''.join(chunks)


def record(sock, limit, deadline):
    data = bytearray()
    while len(data) < limit:
        chunk = exact(sock, 1, deadline)
        if chunk == b'\0':
            return bytes(data)
        data.extend(chunk)
    raise ValueError('oversized protocol record')


def serve_client(client, upstream, allowed_uids, max_bytes, timeout, authenticated_tls=False):
    """Forward one bounded stream only after authenticating the kernel peer UID."""
    started = time.monotonic()
    total = 0
    verdict = 'error'
    try:
        with client:
            if authenticated_tls:
                if not isinstance(client, ssl.SSLSocket) or not client.getpeercert():
                    raise PermissionError('verified client certificate required')
            else:
                _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid not in allowed_uids:
                    raise PermissionError('unapproved peer')
            deadline = started + timeout
            command = record(client, 32, deadline)
            if command != b'zINSTREAM':
                raise ValueError('only INSTREAM is allowed')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as scanner:
                scanner.settimeout(max(0.1, deadline - time.monotonic()))
                scanner.connect(upstream)
                scanner.sendall(b'zINSTREAM\0')
                while True:
                    raw_length = exact(client, 4, deadline)
                    size = struct.unpack('!I', raw_length)[0]
                    if size > 65536 or total + size > max_bytes:
                        raise ValueError('stream limit exceeded')
                    scanner.settimeout(max(0.1, deadline - time.monotonic()))
                    scanner.sendall(raw_length)
                    if size == 0:
                        break
                    block = exact(client, size, deadline)
                    scanner.sendall(block)
                    total += size
                reply = record(scanner, 4096, deadline)
                if reply == b'stream: OK':
                    verdict = 'clean'
                elif reply.startswith(b'stream: ') and reply.endswith(b' FOUND'):
                    verdict = 'blocked'
                else:
                    raise ValueError('scanner did not complete successfully')
                client.settimeout(max(0.1, deadline - time.monotonic()))
                client.sendall(reply + b'\0')
    except (OSError, ValueError, TimeoutError):
        # Closing the socket makes the caller fail closed. No file paths are accepted.
        try:
            client.close()
        except OSError:
            pass
    finally:
        print(json.dumps({'scan_proxy': verdict, 'bytes': total,
                          'duration_ms': int((time.monotonic() - started) * 1000)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    endpoint = parser.add_mutually_exclusive_group(required=True)
    endpoint.add_argument('--listen')
    endpoint.add_argument('--listen-tls', help='127.0.0.1:port only; mutual TLS required')
    parser.add_argument('--tls-cert')
    parser.add_argument('--tls-key')
    parser.add_argument('--tls-ca')
    parser.add_argument('--upstream', required=True)
    parser.add_argument('--allowed-uid', type=int, action='append', default=[])
    parser.add_argument('--max-bytes', type=int, default=20 * 1024 * 1024)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--timeout', type=int, default=15)
    args = parser.parse_args()
    if not (1 <= args.workers <= 8 and 1 <= args.timeout <= 60 and 1 <= args.max_bytes <= 100 * 1024 * 1024):
        parser.error('unsafe resource limits')
    tls = None
    if args.listen_tls:
        host, separator, port = args.listen_tls.partition(':')
        if host != '127.0.0.1' or not separator or not port.isdigit() or not 1024 <= int(port) <= 65535:
            parser.error('TLS listener must use 127.0.0.1 and a non-privileged port')
        if not all(p and os.path.isabs(p) for p in (args.tls_cert, args.tls_key, args.tls_ca)):
            parser.error('TLS certificate, key and dedicated client CA are required')
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        tls.load_cert_chain(args.tls_cert, args.tls_key)
        tls.load_verify_locations(cafile=args.tls_ca)
        tls.verify_mode = ssl.CERT_REQUIRED
    elif not args.allowed_uid:
        parser.error('Unix listener requires at least one allowed peer UID')
    if not os.path.isabs(args.upstream) or (args.listen and
            (not os.path.isabs(args.listen) or args.listen == args.upstream)):
        parser.error('distinct absolute Unix socket paths required')
    if args.listen and os.path.lexists(args.listen):
        previous = os.lstat(args.listen)
        if not stat.S_ISSOCK(previous.st_mode) or previous.st_uid != os.geteuid():
            raise ValueError('refusing to replace an unexpected socket entry')
        os.unlink(args.listen)
    slots = threading.BoundedSemaphore(args.workers)
    with socket.socket(socket.AF_INET if tls else socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        if tls:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, int(port)))
        else:
            listener.bind(args.listen)
            os.chmod(args.listen, 0o660)
        listener.listen(args.workers)
        print(json.dumps({'ready': True, 'workers': args.workers}), flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            while True:
                client, _ = listener.accept()
                if not slots.acquire(blocking=False):
                    client.close()
                    continue
                def handle(connection=client):
                    try:
                        if tls:
                            connection.settimeout(3)
                            connection = tls.wrap_socket(connection, server_side=True)
                        serve_client(connection, args.upstream, set(args.allowed_uid), args.max_bytes,
                                     args.timeout, authenticated_tls=tls is not None)
                    except (OSError, ssl.SSLError):
                        connection.close()
                    finally:
                        slots.release()
                pool.submit(handle)


if __name__ == '__main__':
    main()
