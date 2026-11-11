"""Upload to internal storage over the :6000 tunnel (#2762)."""

import hashlib
import json
import socket
import struct
import threading

import pytest

from backend.app.services import bambu_tunnel
from backend.app.services.bambu_tunnel import TunnelError, _Tunnel


def _read_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = b""
    while len(header) < 16:
        header += sock.recv(16 - len(header))
    length, magic, _seq, _ = struct.unpack("<IIII", header)
    payload = b""
    while len(payload) < length:
        payload += sock.recv(length - len(payload))
    return magic, payload


def _send_json(sock: socket.socket, obj: dict) -> None:
    body = json.dumps(obj).encode()
    sock.sendall(struct.pack("<IIII", len(body), 0x0002013F, 0, 0) + body)


def _fake_printer(sock, received: dict, *, login_result=0, init_result=1, final_result=0, chunk_kb=1):
    magic, payload = _read_frame(sock)
    received["login"] = (magic, payload)
    sock.sendall(struct.pack("<IIII", 4, 0x0001013F, 0, 0) + b"\0\0\0\0")
    _read_frame(sock)  # setup
    _send_json(sock, {"mtype": 12291, "sequence": 0, "result": login_result, "reply": {}})
    if login_result:
        return
    _, payload = _read_frame(sock)
    received["init"] = json.loads(payload)
    _send_json(
        sock, {"cmdtype": 5, "result": init_result, "sequence": 1, "reply": {"chunk_size": chunk_kb, "offset": 0}}
    )
    if init_result not in (1, 19):
        return
    data, chunks = b"", []
    while True:
        _, payload = _read_frame(sock)
        head, chunk = payload.split(b"\n\n", 1)
        req = json.loads(head)["req"]
        chunks.append(req)
        data += chunk
        if "file_md5" in req:
            break
    received["data"], received["chunks"] = data, chunks
    _send_json(sock, {"cmdtype": 5, "result": final_result, "sequence": 1})


def _tunnel_with(printer, **kwargs):
    client, server = socket.socketpair()
    received: dict = {}
    thread = threading.Thread(target=printer, args=(server, received), kwargs=kwargs, daemon=True)
    thread.start()
    tunnel = _Tunnel.__new__(_Tunnel)
    tunnel._sock, tunnel._seq, tunnel._buf = client, 1, bytearray()
    return tunnel, received, thread


def test_upload_sends_pipelined_chunks_with_md5_on_last():
    data = bytes(range(256)) * 10  # 2560 bytes -> three 1 KiB chunks
    tunnel, received, thread = _tunnel_with(_fake_printer)
    progress = []
    tunnel.login("12345678")
    tunnel.upload(data, "cube.gcode.3mf", lambda done, total: progress.append(done))
    thread.join(2)

    magic, login = received["login"]
    assert magic == 0x0101013F and login == b"bblp" + b"\0" * 4 + b"12345678"
    assert received["init"]["req"] == {"type": "model", "storage": "emmc", "path": "cube.gcode.3mf", "total": 2560}
    assert received["data"] == data
    assert [c["offset"] for c in received["chunks"]] == [0, 1024, 2048]
    assert "file_md5" not in received["chunks"][0]
    assert received["chunks"][-1]["file_md5"] == hashlib.md5(data).hexdigest()  # noqa: S324
    assert progress[-1] == 2560


def test_existing_name_is_overwritten_not_refused():
    tunnel, received, thread = _tunnel_with(_fake_printer, init_result=19)
    tunnel.login("12345678")
    tunnel.upload(b"x" * 10, "cube.gcode.3mf")
    thread.join(2)
    assert received["data"] == b"x" * 10


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"login_result": 1}, "login refused"),
        ({"init_result": 2}, "at init"),
        ({"final_result": -9203}, "upload failed"),
    ],
)
def test_refusals_raise(kwargs, message):
    tunnel, _received, thread = _tunnel_with(_fake_printer, **kwargs)
    with pytest.raises(TunnelError, match=message):
        tunnel.login("12345678")
        tunnel.upload(b"x" * 10, "cube.gcode.3mf")
    thread.join(2)


def test_module_upload_reads_file_and_closes(tmp_path, monkeypatch):
    path = tmp_path / "cube.gcode.3mf"
    path.write_bytes(b"abc")
    calls = []

    class FakeTunnel:
        def __init__(self, host, timeout):
            calls.append(("open", host))

        def login(self, code):
            calls.append(("login", code))

        def upload(self, data, name, progress_callback):
            calls.append(("upload", data, name))

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(bambu_tunnel, "_Tunnel", FakeTunnel)
    bambu_tunnel.upload_to_internal_storage("printer", "12345678", path, "cube.gcode.3mf")
    assert calls == [("open", "printer"), ("login", "12345678"), ("upload", b"abc", "cube.gcode.3mf"), ("close",)]
