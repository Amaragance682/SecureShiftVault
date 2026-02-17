# src/net_protocol.py
from __future__ import annotations
import json
import struct
from typing import Any, Dict

# code basically sends json objects over a byte stream




def send_msg(sock, obj: Dict[str, Any]) -> None: # basically a python dict sent as a json message
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8") # object -> JSON string -> UTF-8 format bytes
    sock.sendall(struct.pack("!I", len(data))) # big endian order, unsigned 4 byte integer
    sock.sendall(data) 

def recv_exact(sock, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out)) # collect bytes
        if not chunk: # if empty the connection is closed
            raise ConnectionError("socket closed")
        out += chunk # counting the data total
    return out

def recv_msg(sock) -> Dict[str, Any]:
    # kept getting split/merged/delayed messages, formatting it like this preserves proper message form
    (length,) = struct.unpack("!I", recv_exact(sock, 4))  # FORMAT: \x00\x00\x00\x1A{"type":"login","user":"oli"}, allows us to read header size
    data = recv_exact(sock, length) # since we know exactly how much to read
    return json.loads(data.decode("utf-8"))