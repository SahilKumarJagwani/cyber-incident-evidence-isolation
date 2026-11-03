"""
Offline link between the Windows Flask app and the sandbox VM.

There is NO network adapter involved. VirtualBox connects the VM's COM1
serial port to a Windows named pipe:

    Flask (this module) +   \\\\.\\pipe\\CyberEvidenceSandbox  -   VM /dev/ttyS0

Evidence bytes are written from memory straight into the pipe, so nothing
is stored on Windows. Every message is a framed, HMAC-authenticated packet
(shared secret = SANDBOX_RECEIVER_TOKEN), so corruption or a stray process
on either end is detected.

Public functions (same names/signatures the Flask app already uses):
    send_evidence_to_sandbox(vault_id, data, original_filename, sha256_hex)
    delete_evidence_from_sandbox(vault_id)
    release_evidence_in_sandbox(vault_id, expected_hash)  
    ping_sandbox()                                        


Environment variables:
    SANDBOX_RECEIVER_TOKEN   shared secret (same as RECEIVER_TOKEN in the VM)
    SANDBOX_PIPE_PATH        default \\\\.\\pipe\\CyberEvidenceSandbox
    SANDBOX_LINK_TIMEOUT     base timeout in seconds (default 30)
"""

import hashlib
import hmac
import json
import os
import struct
import sys
import threading
import time
import uuid

MAGIC = b"EVD1"
MAX_HEADER = 8192
MAX_BODY = 5 * 1024 * 1024 + 1024
MAC_LEN = 32

# Extra time allowed per byte sent, on top of the base timeout.
ASSUMED_BYTES_PER_SECOND = 10 * 1024


class SandboxError(Exception):
    """Raised when the sandbox cannot be reached or rejects a request."""


def _token():
    return os.environ.get("SANDBOX_RECEIVER_TOKEN", "")


def _path():
    return os.environ.get("SANDBOX_PIPE_PATH", r"\\.\pipe\CyberEvidenceSandbox")


def _base_timeout():
    return float(os.environ.get("SANDBOX_LINK_TIMEOUT", "30"))


# framing 

def _mac(key, lengths, header, body):
    digest = hmac.new(key, digestmod=hashlib.sha256)
    digest.update(lengths)
    digest.update(header)
    digest.update(body)
    return digest.digest()


def encode_frame(key, header_dict, body=b""):
    header = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
    lengths = struct.pack(">II", len(header), len(body))
    return MAGIC + lengths + header + body + _mac(key, lengths, header, body)


class _Reader:
    """Buffered reader that can resynchronise on the frame magic."""

    def __init__(self, port):
        self.port = port
        self.buf = bytearray()

    def _fill(self, idle=None):
        data = self.port.read(65536, idle)
        if not data:
            raise EOFError("link closed")
        self.buf += data

    def need(self, count, idle=None):
        while len(self.buf) < count:
            self._fill(idle)

    def find_magic(self):
        while True:
            index = self.buf.find(MAGIC)
            if index >= 0:
                del self.buf[:index + len(MAGIC)]
                return
            del self.buf[:max(0, len(self.buf) - (len(MAGIC) - 1))]
            self._fill()


def read_frame(reader, key, idle=None):
    """Return (header_dict, body) of the next valid frame."""

    while True:
        reader.find_magic()
        try:
            reader.need(8, idle)
            header_len, body_len = struct.unpack(">II", bytes(reader.buf[:8]))
            if not (0 < header_len <= MAX_HEADER) or body_len > MAX_BODY:
                continue
            total = 8 + header_len + body_len + MAC_LEN
            reader.need(total, idle)
        except TimeoutError:
            if idle is None:
                raise
            continue

        lengths = bytes(reader.buf[:8])
        header = bytes(reader.buf[8:8 + header_len])
        body = bytes(reader.buf[8 + header_len:8 + header_len + body_len])
        mac = bytes(reader.buf[8 + header_len + body_len:total])

        if hmac.compare_digest(mac, _mac(key, lengths, header, body)):
            try:
                parsed = json.loads(header)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                del reader.buf[:total]
                return parsed, body
        # Bad frame: the magic is already consumed; keep scanning the rest.


# ports

class _WindowsPipe:
    """Client end of the VirtualBox named pipe, with a hard timeout."""

    def __init__(self, path):
        self._f = open(path, "r+b", buffering=0)
        self._timer = None
        self.timed_out = False

    def arm(self, seconds):
        self.disarm()
        self.timed_out = False
        self._timer = threading.Timer(seconds, self._abort)
        self._timer.daemon = True
        self._timer.start()

    def disarm(self):
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _abort(self):
        # Cancel a blocked ReadFile/WriteFile issued by another thread.
        self.timed_out = True
        try:
            import ctypes
            import msvcrt
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            kernel32.CancelIoEx.restype = wintypes.BOOL
            kernel32.CancelIoEx(msvcrt.get_osfhandle(self._f.fileno()), None)
        except Exception:
            pass

    def read(self, count, idle=None):
        if self.timed_out:
            raise TimeoutError("link timed out")
        try:
            return self._f.read(count)
        except OSError:
            if self.timed_out:
                raise TimeoutError("link timed out") from None
            raise

    def write(self, data):
        view = memoryview(data)
        while len(view):
            if self.timed_out:
                raise TimeoutError("link timed out")
            try:
                written = self._f.write(view[:16384])
            except OSError:
                if self.timed_out:
                    raise TimeoutError("link timed out") from None
                raise
            if not written:
                raise OSError("pipe closed")
            view = view[written:]

    def close(self):
        self.disarm()
        try:
            self._f.close()
        except OSError:
            pass


class _PosixPort:
    """Serial/tty end for Linux/macOS (used for testing and development)."""

    def __init__(self, path):
        import tty
        self._fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
        tty.setraw(self._fd)
        self._deadline = None

    def arm(self, seconds):
        self._deadline = time.monotonic() + seconds

    def disarm(self):
        self._deadline = None

    def _wait(self, for_write):
        import select
        while True:
            remaining = None
            if self._deadline is not None:
                remaining = self._deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("link timed out")
            readable, writable, _ = select.select(
                [] if for_write else [self._fd],
                [self._fd] if for_write else [],
                [], remaining)
            if readable or writable:
                return

    def read(self, count, idle=None):
        self._wait(False)
        return os.read(self._fd, count)

    def write(self, data):
        view = memoryview(data)
        while len(view):
            self._wait(True)
            written = os.write(self._fd, view[:4096])
            view = view[written:]

    def close(self):
        try:
            os.close(self._fd)
        except OSError:
            pass


def _open_port(path):
    return _WindowsPipe(path) if os.name == "nt" else _PosixPort(path)


# transport

_lock = threading.Lock()   # the serial link carries one request at a time
_port = None


def _close_port():
    global _port
    if _port is not None:
        _port.close()
        _port = None


def _transact(request, body=b""):
    global _port

    token = _token()
    if not token:
        raise SandboxError("SANDBOX_RECEIVER_TOKEN is not set.")

    key = token.encode("utf-8")
    nonce = os.urandom(8).hex()
    frame = encode_frame(key, dict(request, nonce=nonce), body)
    timeout = _base_timeout() + len(body) / ASSUMED_BYTES_PER_SECOND

    with _lock:
        if _port is None:
            try:
                _port = _open_port(_path())
            except OSError as error:
                raise SandboxError(
                    f"Sandbox link unavailable ({_path()}): {error}. "
                    "Is the VM running?"
                ) from error

        port = _port
        try:
            port.arm(timeout)
            port.write(frame)

            reader = _Reader(port)
            while True:
                reply, _ = read_frame(reader, key)
                if reply.get("nonce") == nonce:
                    break
            port.disarm()
        except (OSError, EOFError) as error:   # TimeoutError is an OSError
            _close_port()
            raise SandboxError(f"Sandbox link failed: {error}") from error

    code = reply.get("code")
    if not isinstance(code, int) or code >= 400:
        raise SandboxError(f"Sandbox returned {code}: {reply.get('error', '')}")
    return reply


# public API

def send_evidence_to_sandbox(vault_id, data, original_filename, sha256_hex):
    """Send evidence bytes (held in memory) to the sandbox vault."""

    reply = _transact(
        {
            "op": "store",
            "id": vault_id,
            "name": original_filename,
            "sha256": sha256_hex,
        },
        data,
    )

    if str(reply.get("sha256", "")).lower() != sha256_hex.lower():
        try:
            delete_evidence_from_sandbox(vault_id)
        except SandboxError:
            pass
        raise SandboxError("Sandbox hash does not match the uploaded file.")


def delete_evidence_from_sandbox(vault_id):
    _transact({"op": "delete", "id": vault_id})


def release_evidence_in_sandbox(vault_id, expected_hash):
    """Ask the sandbox to re-verify the hash and move the file to analysis."""

    return _transact({"op": "release", "id": vault_id, "sha256": expected_hash})


def ping_sandbox():
    return _transact({"op": "ping"})


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "ping"
    try:
        if command == "ping":
            print("OK:", ping_sandbox())
        elif command == "speed":
            megabytes = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
            blob = os.urandom(int(megabytes * 1024 * 1024))
            test_id = uuid.uuid4().hex
            started = time.time()
            send_evidence_to_sandbox(
                test_id, blob, "speedtest.txt", hashlib.sha256(blob).hexdigest()
            )
            elapsed = time.time() - started
            delete_evidence_from_sandbox(test_id)
            print(f"Sent {len(blob) / 1024:.0f} KB in {elapsed:.1f}s "
                  f"({len(blob) / 1024 / elapsed:.0f} KB/s). Test file removed.")
        else:
            print("Usage: python sandbox_link.py [ping|speed <MB>]")
    except SandboxError as error:
        print("FAILED:", error)
        sys.exit(1)