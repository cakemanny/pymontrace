import os

from pymontrace import _mapbuffer

__all__ = ['create']


class MapBuffer:
    def __init__(self, _mb) -> None:
        self._mb = _mb

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
        return mb.write(data)


def create(filename: str) -> MapBuffer:
    fd = os.open(filename, os.O_CREAT | os.O_RDWR)
    os.ftruncate(fd, 1 << 14)
    with open(filename, 'a+b') as f:
        mb = _mapbuffer.create(f.fileno())
    return MapBuffer(mb)
