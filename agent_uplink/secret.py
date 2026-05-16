from __future__ import annotations

import ctypes
import logging
import mmap
import os
import uuid
from pathlib import Path

LOGGER = logging.getLogger("agent-uplink")

_libc = ctypes.CDLL("libc.so.6", use_errno=True)

# /dev/shm is tmpfs on Linux: contents live in memory, never on disk. We use
# it instead of memfd_create because docker/runc refuses to bind-mount the
# magic /proc/<pid>/fd/<N> path of an anonymous memfd (mount(2) returns
# EINVAL — the inode is unlinked and has no mountable path).
_SHM_DIR = Path("/dev/shm")


def _mlock(addr: int, length: int) -> None:
    if _libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length)) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"mlock failed: {os.strerror(errno)}")


def _munlock(addr: int, length: int) -> None:
    _libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))


class LockedSecret:
    """In-memory tmpfs file holding secret bytes.

    Backed by a 0600 file under /dev/shm (tmpfs, so contents never hit disk)
    with its pages mlock'd against swap. close() zeroes the content before
    unlinking, so freed pages don't sit in the page allocator with stale data.

    Pass `bind_source` as a docker `-v` source. A container's bind mount keeps
    the underlying inode alive even after the host path is unlinked, so
    close() must run *after* such containers have stopped.
    """

    def __init__(self, name: str, payload: bytes) -> None:
        self._fd: int | None = None
        self._mmap: mmap.mmap | None = None
        self._path: Path | None = None
        self._length = len(payload)
        if self._length == 0:
            raise ValueError("LockedSecret payload must be non-empty")

        path = _SHM_DIR / f"agent-uplink-{name}-{os.getpid()}-{uuid.uuid4().hex}"
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.ftruncate(fd, self._length)
            written = os.write(fd, payload)
            if written != self._length:
                raise OSError(f"short write to tmpfs: {written}/{self._length}")
            m = mmap.mmap(fd, self._length, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            try:
                addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
                _mlock(addr, self._length)
            except OSError:
                m.close()
                raise
        except BaseException:
            os.close(fd)
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise

        self._fd = fd
        self._mmap = m
        self._path = path

    @property
    def bind_source(self) -> str:
        if self._path is None:
            raise RuntimeError("LockedSecret is closed")
        return str(self._path)

    def close(self) -> None:
        if self._mmap is not None:
            try:
                addr = ctypes.addressof(ctypes.c_char.from_buffer(self._mmap))
                self._mmap[:] = b"\x00" * self._length
                _munlock(addr, self._length)
            except Exception:
                LOGGER.warning("failed to scrub locked secret", exc_info=True)
            self._mmap.close()
            self._mmap = None
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        if self._path is not None:
            try:
                self._path.unlink()
            except FileNotFoundError:
                pass
            self._path = None

    def __del__(self) -> None:
        self.close()
