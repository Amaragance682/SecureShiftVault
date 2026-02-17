# src/client.py
from __future__ import annotations

import argparse
import socket
import ssl
from typing import Any, Dict, Optional

from .net_protocol import send_msg, recv_msg

def make_socket(host: str, port: int, tls: bool, ca_file: str = "", server_name: str = ""):
    raw = socket.create_connection((host, port), timeout=5.0)
    if not tls:
        return raw

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    # For a self-signed cert, ship server.crt and trust it explicitly:
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    else:
        raise ValueError("TLS enabled but no --ca provided (need server cert/CA)")

    return ctx.wrap_socket(raw, server_hostname=server_name)

def rpc(host: str, port: int, req: Dict[str, Any], tls: bool, ca_file: str, server_name: str) -> Dict[str, Any]:
    s = make_socket(host, port, tls, ca_file=ca_file, server_name=server_name)
    with s:
        send_msg(s, req)
        return recv_msg(s)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--ca", default="", help="CA/server cert file to trust (e.g., server.crt)")
    p.add_argument("--server-name", default="localhost", help="must match certificate CN/SAN")

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("register")
    s.add_argument("username")
    s.add_argument("pin")

    s = sub.add_parser("login")
    s.add_argument("username")
    s.add_argument("pin")

    s = sub.add_parser("clockin")
    s.add_argument("token")
    s.add_argument("pin")
    s.add_argument("--task", required=True)
    s.add_argument("--location", required=True)
    s.add_argument("--notes", default="")

    s = sub.add_parser("clockout")
    s.add_argument("token")
    s.add_argument("pin")
    s.add_argument("--notes", default="")

    s = sub.add_parser("list")
    s.add_argument("token")
    s.add_argument("pin")

    args = p.parse_args()

    if args.cmd == "register":
        req = {"cmd": "register", "username": args.username, "pin": args.pin}
    elif args.cmd == "login":
        req = {"cmd": "login", "username": args.username, "pin": args.pin}
    elif args.cmd == "clockin":
        req = {"cmd": "clockin", "token": args.token, "pin": args.pin,
               "task": args.task, "location": args.location, "notes": args.notes}
    elif args.cmd == "clockout":
        req = {"cmd": "clockout", "token": args.token, "pin": args.pin, "notes": args.notes}
    else:
        req = {"cmd": "list", "token": args.token, "pin": args.pin}

    resp = rpc(args.host, args.port, req, tls=args.tls, ca_file=args.ca, server_name=args.server_name)
    print(resp)

if __name__ == "__main__":
    main()