# src/server_tls.py
from __future__ import annotations

import os
import ssl
import socket

from .plaintext_server import handle_request
from .net_protocol import send_msg, recv_msg

HOST = "127.0.0.1"
PORT = 5443

CERT_FILE = "server.crt"
KEY_FILE = "server.key"

def build_tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION  # mitigate CRIME-style compression issues

    # found this for TLS 1.3 in the TLS 1.3 specification
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!3DES")

    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return ctx

def serve(db_path: str) -> None:
    tls_ctx = build_tls_context()
    with socket.create_server((HOST, PORT)) as srv:
        print(f"[tls] listening on {HOST}:{PORT}, db={os.path.abspath(db_path)}")
        while True:
            raw_conn, addr = srv.accept()
            with raw_conn:
                try:
                    with tls_ctx.wrap_socket(raw_conn, server_side=True) as conn:
                        req = recv_msg(conn)
                        resp = handle_request(req, db_path)
                        send_msg(conn, resp)
                except Exception as e:
                    # If handshake fails, you shouldnt get any reply
                    pass

if __name__ == "__main__":
    serve("vault.db")