"""A stand-in for the attacker's C2 drop server.

Listens on 127.0.0.1:<port>, accepts a raw HTTP POST, records the exfiltrated
body to a file, and answers 200. Prints one line per byte-carrying hit so the
demo can show, concretely, whether stolen data actually arrived.

Usage: python demo/attacker_sink.py <port> <record_file>
"""
from __future__ import annotations

import socket
import sys
import threading


def _handle(conn: socket.socket, record_path: str) -> None:
    with conn:
        conn.settimeout(4)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            header, _, body = data.partition(b"\r\n\r\n")
            clen = 0
            for line in header.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    clen = int(line.split(b":", 1)[1].strip() or b"0")
            while len(body) < clen:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body += chunk
            if body:
                with open(record_path, "ab") as fh:
                    fh.write(body + b"\n")
                print(f"[attacker-sink] STOLEN {len(body)} bytes: {body[:80]!r}",
                      flush=True)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass


def main() -> int:
    port = int(sys.argv[1])
    record_path = sys.argv[2]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    print(f"[attacker-sink] listening on 127.0.0.1:{port}", flush=True)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=_handle, args=(conn, record_path), daemon=True).start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
