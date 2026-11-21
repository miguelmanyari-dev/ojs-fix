import importlib.util
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest

SPEC = importlib.util.spec_from_file_location('scan_proxy', str(Path(__file__).resolve().parents[1] / 'tools/scan_proxy.py'))
proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proxy)


class ProxyTests(unittest.TestCase):
    def handle(self, payload, reply=b'stream: OK\0', limit=4096, approved=True):
        with tempfile.TemporaryDirectory() as directory:
            path = directory + '/scanner.sock'
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(path)
            listener.listen(1)
            listener.settimeout(0.3)
            received = []
            def upstream():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(1)
                        received.append(proxy.record(connection, 32, time.monotonic() + 1))
                        data = bytearray()
                        while True:
                            length = struct.unpack('!I', proxy.exact(connection, 4, time.monotonic() + 1))[0]
                            if not length:
                                break
                            data.extend(proxy.exact(connection, length, time.monotonic() + 1))
                        received.append(bytes(data))
                        connection.sendall(reply)
                except (OSError, ValueError):
                    pass
            backend = threading.Thread(target=upstream)
            backend.start()
            caller, server = socket.socketpair()
            caller.settimeout(1)
            worker = threading.Thread(target=proxy.serve_client, args=(server, path,
                {os.getuid()} if approved else {os.getuid() + 10000}, limit, 1))
            worker.start()
            try:
                caller.sendall(payload)
                caller.shutdown(socket.SHUT_WR)
                answer = b''
                while True:
                    chunk = caller.recv(4096)
                    if not chunk:
                        break
                    answer += chunk
            except OSError:
                answer = b''
            finally:
                caller.close()
                worker.join(2)
                backend.join(2)
                listener.close()
            return answer, received

    def test_clean_stream_only(self):
        data = b'harmless document'
        answer, received = self.handle(b'zINSTREAM\0' + struct.pack('!I', len(data)) + data + b'\0' * 4)
        self.assertEqual(b'stream: OK\0', answer)
        self.assertEqual([b'zINSTREAM', data], received)

    def test_administrative_and_path_commands_never_reach_scanner(self):
        for command in (b'zSHUTDOWN\0', b'zRELOAD\0', b'zSCAN /etc/passwd\0', b'zFILDES\0'):
            with self.subTest(command=command):
                answer, received = self.handle(command)
                self.assertEqual(b'', answer)
                self.assertEqual([], received)

    def test_unapproved_peer_and_oversized_stream_are_rejected(self):
        answer, received = self.handle(b'zINSTREAM\0\0\0\0\0', approved=False)
        self.assertEqual(b'', answer)
        self.assertEqual([], received)
        answer, _ = self.handle(b'zINSTREAM\0' + struct.pack('!I', 4097), limit=4096)
        self.assertEqual(b'', answer)

    def test_infected_reply_preserved_and_error_never_clean(self):
        frame = b'zINSTREAM\0\0\0\0\0'
        answer, _ = self.handle(frame, reply=b'stream: Eicar-Signature FOUND\0')
        self.assertEqual(b'stream: Eicar-Signature FOUND\0', answer)
        answer, _ = self.handle(frame, reply=b'stream: size limit ERROR\0')
        self.assertEqual(b'', answer)

    def test_truncated_frame_fails_closed(self):
        answer, _ = self.handle(b'zINSTREAM\0\0\0')
        self.assertEqual(b'', answer)
