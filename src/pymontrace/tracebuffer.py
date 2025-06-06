import os
import threading

from pymontrace import _tracebuffer

__all__ = ['create']


PAGESIZE = os.sysconf("SC_PAGE_SIZE")
DEFAULT_BUFFER_SIZE = (1 << 20)  # 1MiB


class TraceBuffer:
    def __init__(self, _mb) -> None:
        self._mb = _mb
        self._lock = threading.Lock()

    def close(self):
        self._mb = None  # __del__ will clean up

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def read(self) -> bytes:
        if (mb := self._mb) is None:
            raise ValueError('I/O operation on closed buffer')
        return mb.read()

    def write(self, data: bytes) -> None:
        if (mb := self._mb) is None:
            raise ValueError('I/O operation on closed buffer')

        if not self._lock.acquire(timeout=1.0):
            raise TimeoutError('failed to acquire lock on TraceBuffer after 1s')
        try:
            return mb.write(data)
        finally:
            self._lock.release()


def create(filename: str, size: int = DEFAULT_BUFFER_SIZE) -> TraceBuffer:
    if size < PAGESIZE or size % PAGESIZE != 0:
        raise ValueError("Invalid size, must a multiple of PAGESIZE")
    fd = os.open(filename, os.O_CREAT | os.O_RDWR)
    os.ftruncate(fd, size)
    with open(fd, 'a+b', buffering=0) as f:  # <- closes the fd
        mb = _tracebuffer.create(f.fileno())
    return TraceBuffer(mb)
