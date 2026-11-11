"""Upload a print to the printer's internal storage over the :6000 tunnel (#2762).

H2-series, P2S and X2D printers keep sliced files on internal eMMC. FTPS on
port 990 only serves external storage, so a printer with no SD card or USB
stick refuses every FTPS upload with 553. Bambu Studio sends to these printers
over "BambuTunnelLocal" on TLS :6000 instead, and the print is then started
with ``url = brtc://emmc/<name>``.

Wire protocol as documented by open-bambu-networking (AGPL-3.0),
https://github.com/ClusterM/open-bambu-networking, research/06.04-port-6000.md:

- Implicit TLS; the printer's certificate is self-signed (CN = serial), so it
  is not verified, the same as our FTPS and MQTT connections.
- Every frame is a 16-byte little-endian header (payload length, magic,
  sequence, 0) followed by the payload.
- Login on subchannel 0x01: ``bblp`` and the LAN access code, 8 bytes each,
  NUL-padded. Then one setup JSON on subchannel 0x02.
- FILE_UPLOAD (cmdtype 5): an init request, answered with ``chunk_size`` in
  KiB; then every chunk back to back with no waiting for acks between them
  (waiting yields -9203 on P2S); the last chunk carries the MD5 of the whole
  file; then exactly one final reply.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import socket
import ssl
import struct
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

TUNNEL_PORT = 6000

_MAGIC_LOGIN = 0x0101013F
_MAGIC_CTRL = 0x0102013F
_MTYPE_SETUP = 12291
_MTYPE_CTRL = 12289
_CMD_UPLOAD = 5

_RESULT_OK = 0
_RESULT_CONTINUE = 1
_RESULT_FILE_EXISTS = 19  # init only: the name exists, upload anyway (overwrites)


class TunnelError(Exception):
    """The :6000 upload failed; the message says at which step."""


class _Tunnel:
    def __init__(self, host: str, timeout: float):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, TUNNEL_PORT), timeout=timeout)
        self._sock = ctx.wrap_socket(raw, server_hostname=host)
        self._seq = random.randint(1, 0x7FFFFFFF)
        self._buf = bytearray()

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def _send(self, magic: int, payload: bytes) -> None:
        header = struct.pack("<IIII", len(payload), magic, self._seq & 0xFFFFFFFF, 0)
        self._seq += 1
        self._sock.sendall(header + payload)

    def _send_json(self, obj: dict, binary: bytes = b"") -> None:
        body = json.dumps({"mtype": _MTYPE_CTRL, **obj}, separators=(",", ":")).encode()
        self._send(_MAGIC_CTRL, body + b"\n\n" + binary if binary else body)

    def _recv_frame(self) -> bytes:
        while True:
            if len(self._buf) >= 16:
                (length,) = struct.unpack_from("<I", self._buf, 0)
                if len(self._buf) >= 16 + length:
                    payload = bytes(self._buf[16 : 16 + length])
                    del self._buf[: 16 + length]
                    return payload
            chunk = self._sock.recv(65536)
            if not chunk:
                raise TunnelError("printer closed the connection")
            self._buf += chunk

    def _recv_json(self) -> dict:
        payload = self._recv_frame()
        text = payload.split(b"\n\n", 1)[0]
        try:
            return json.loads(text)
        except ValueError as e:
            raise TunnelError(f"unreadable reply: {text[:80]!r}") from e

    def login(self, access_code: str) -> None:
        user = b"bblp".ljust(8, b"\0")
        code = access_code.encode("ascii", "replace")[:8].ljust(8, b"\0")
        self._send(_MAGIC_LOGIN, user + code)
        self._recv_frame()  # login ack, four zero bytes
        setup = {
            "sequence": 0,
            "mtype": _MTYPE_SETUP,
            "req": {"t_av": 0, "mtype": _MTYPE_CTRL, "peer_t": 3, "pid": "", "ver": ""},
        }
        self._send(_MAGIC_CTRL, json.dumps(setup, separators=(",", ":")).encode())
        reply = self._recv_json()
        if reply.get("result") != _RESULT_OK:
            raise TunnelError(f"login refused (result={reply.get('result')}); check the access code")

    def upload(
        self,
        data: bytes,
        remote_name: str,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        total = len(data)
        seq = 1
        init = {"type": "model", "storage": "emmc", "path": remote_name, "total": total}
        self._send_json({"cmdtype": _CMD_UPLOAD, "sequence": seq, "req": init})
        reply = self._recv_json()
        if reply.get("result") not in (_RESULT_CONTINUE, _RESULT_FILE_EXISTS):
            raise TunnelError(f"upload refused at init (result={reply.get('result')})")
        chunk_size = int((reply.get("reply") or {}).get("chunk_size") or 0) * 1024
        if chunk_size <= 0:
            raise TunnelError("printer gave no chunk size")

        md5 = hashlib.md5()  # noqa: S324 - integrity check required by the protocol
        offset = 0
        frag_id = 0
        while offset < total or frag_id == 0:
            chunk = data[offset : offset + chunk_size]
            md5.update(chunk)
            req = {"frag_id": frag_id, "offset": offset, "size": len(chunk)}
            if offset + len(chunk) >= total:
                req["file_md5"] = md5.hexdigest()
            self._send_json({"cmdtype": _CMD_UPLOAD, "sequence": seq, "req": req}, chunk)
            offset += len(chunk)
            frag_id += 1
            if progress_callback:
                progress_callback(offset, total)

        reply = self._recv_json()
        if reply.get("result") != _RESULT_OK:
            raise TunnelError(f"upload failed (result={reply.get('result')})")


def upload_to_internal_storage(
    host: str,
    access_code: str,
    local_path: Path,
    remote_name: str,
    *,
    timeout: float = 60.0,
    progress_callback: Callable[[int, int], None] | None = None,
) -> None:
    """Upload ``local_path`` to internal storage as ``remote_name``. Raises on failure.

    The file lands in the printer's model cache; start it with
    ``brtc://emmc/<remote_name>``. The cache keeps the last 8 uploads.
    """
    data = Path(local_path).read_bytes()
    tunnel = _Tunnel(host, timeout)
    try:
        tunnel.login(access_code)
        tunnel.upload(data, remote_name, progress_callback)
    finally:
        tunnel.close()
    logger.info("Uploaded %s (%d bytes) to %s internal storage over :6000", remote_name, len(data), host)


async def upload_to_internal_storage_async(
    host: str,
    access_code: str,
    local_path: Path,
    remote_name: str,
    *,
    timeout: float = 60.0,
    progress_callback: Callable[[int, int], None] | None = None,
) -> None:
    await asyncio.to_thread(
        upload_to_internal_storage,
        host,
        access_code,
        local_path,
        remote_name,
        timeout=timeout,
        progress_callback=progress_callback,
    )
