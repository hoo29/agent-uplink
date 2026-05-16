from __future__ import annotations

import ctypes
import logging
import mmap
import os

LOGGER = logging.getLogger("agent-uplink")

_libc = ctypes.CDLL("libc.so.6", use_errno=True)


def _mlock(addr: int, length: int) -> None:
    if _libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length)) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"mlock failed: {os.strerror(errno)}")


def _munlock(addr: int, length: int) -> None:
    _libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))


class LockedSecret:
    """Anonymous in-memory file holding secret bytes.

    Backed by memfd_create + mlock so the payload never touches a filesystem
    and cannot be paged to swap. close() zeroes the content before releasing
    the fd, so freed pages don't sit in the page allocator with stale data.

    Pass `bind_source` as a docker `-v` source. A container's bind mount keeps
    the underlying inode alive even after this process closes the fd, so
    close() must run *after* such containers have stopped.
    """

    def __init__(self, name: str, payload: bytes) -> None:
        self._fd: int | None = None
        self._mmap: mmap.mmap | None = None
        self._length = len(payload)
        if self._length == 0:
            raise ValueError("LockedSecret payload must be non-empty")

        fd = os.memfd_create(name, 0)
        try:
            os.ftruncate(fd, self._length)
            written = os.write(fd, payload)
            if written != self._length:
                raise OSError(f"short write to memfd: {written}/{self._length}")
            m = mmap.mmap(fd, self._length, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            try:
                addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
                _mlock(addr, self._length)
            except OSError:
                m.close()
                raise
        except BaseException:
            os.close(fd)
            raise

        self._fd = fd
        self._mmap = m

    @property
    def bind_source(self) -> str:
        if self._fd is None:
            raise RuntimeError("LockedSecret is closed")
        return f"/proc/{os.getpid()}/fd/{self._fd}"

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

    def __del__(self) -> None:
        self.close()
