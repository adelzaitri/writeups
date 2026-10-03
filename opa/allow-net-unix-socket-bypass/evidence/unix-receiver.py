#!/usr/bin/env python3
"""Synthetic UNIX-socket HTTP receiver for the opa Lead 1 lab.

Logs the verbatim bytes of every request it receives to unix.log and answers
with a small JSON body carrying the run marker, so that "a fetch happened" is
distinguishable from "a connect happened".

NEVER point the lab at a real container-runtime socket. This receiver is the
whole of what the finding needs.
"""
import os
import socket
import sys

sock_path = sys.argv[1]
log_path = sys.argv[2]
marker = sys.argv[3]

try:
    os.unlink(sock_path)
except FileNotFoundError:
    pass

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
os.chmod(sock_path, 0o777)
s.listen(8)

body = ('{"marker":"%s"}' % marker).encode()
with open(log_path, "a", buffering=1) as log:
    log.write("=== receiver listening on %s ===\n" % sock_path)
    while True:
        conn, _ = s.accept()
        data = conn.recv(8192)
        log.write(repr(data) + "\n")
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        conn.close()
