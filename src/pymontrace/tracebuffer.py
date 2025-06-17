import os
import pickle
import threading
from typing import Union

from pymontrace import _tracebuffer

__all__ = [
    'create', 'create_agg_buffer', 'open_agg_buffer', 'encode_entry',
    'encode_value', 'decode_value'
]


PAGESIZE = os.sysconf("SC_PAGE_SIZE")
DEFAULT_BUFFER_SIZE = (1 << 20)  # 1MiB


class TraceBuffer:
    def __init__(self, _tb) -> None:
        self._tb = _tb
        self._lock = threading.Lock()

    def close(self):
        self._tb = None  # __del__ will clean up

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def read(self) -> bytes:
        if (tb := self._tb) is None:
            raise ValueError('I/O operation on closed buffer')
        return tb.read()

    def write(self, data: bytes) -> None:
        if (tb := self._tb) is None:
            raise ValueError('I/O operation on closed buffer')

        if not self._lock.acquire(timeout=1.0):
            raise TimeoutError('failed to acquire lock on TraceBuffer after 1s')
        try:
            return tb.write(data)
        finally:
            self._lock.release()


def create(filename: str, size: int = DEFAULT_BUFFER_SIZE) -> TraceBuffer:
    if size < PAGESIZE or size % PAGESIZE != 0:
        raise ValueError("Invalid size, must a multiple of PAGESIZE")
    fd = os.open(filename, os.O_CREAT | os.O_RDWR)
    os.ftruncate(fd, size)
    with open(fd, 'a+b', buffering=0) as f:  # <- closes the fd
        tb = _tracebuffer.create(f.fileno())
    return TraceBuffer(tb)


class AggBuffer:
    def __init__(self, _agg_buffer, fn: str) -> None:
        self._agg_buffer = _agg_buffer
        self.fn = fn
        self._lock = threading.Lock()
        self.epoch = 2

    @property
    def name(self) -> str:  # tracer
        return self._agg_buffer.name

    @property
    def agg_op(self):  # tracer
        return self._agg_buffer.agg_op

    @agg_op.setter
    def agg_op(self, value: int):  # tracee
        self._agg_buffer.agg_op = value

    def __enter__(self):
        if not self._lock.acquire(timeout=1.0):
            raise TimeoutError('failed to acquire lock on AggBuffer after 1s')
        self.epoch = self._agg_buffer.epoch

    def __exit__(self, exc_type, exc_value, traceback):
        self._lock.release()

    def read(self, offset: int, size: int) -> bytes:  # tracee
        return self._agg_buffer.read(self.epoch, offset, size)

    def write(self, kvp: bytes) -> tuple[int, int]:  # tracee
        return self._agg_buffer.write(self.epoch, kvp)

    def update(self, kvp: bytes, offset: int, size: int) -> bytes:  # tracee
        return self._agg_buffer.update(self.epoch, kvp, offset, size)

    def readall(self, epoch: Union[int, None] = None) -> bytes:  # tracer
        if epoch is None:
            epoch = self.epoch
        return self._agg_buffer.readall(epoch)

    def written(self, epoch: int) -> int:  # tracer
        """The number of bytes already written to epoch buffer"""
        return self._agg_buffer.written(epoch)

    def switch(self):  # tracer
        """Switch the active buffer and increment the epoch"""
        # Maybe this should just be combined into a single C function?
        self._agg_buffer.reset(self.epoch - 1)
        self.epoch = self._agg_buffer.incr_epoch()


def create_agg_buffer(name: str, filename: str, size=DEFAULT_BUFFER_SIZE) -> AggBuffer:
    with open(filename, 'x+b', buffering=0) as f:
        f.truncate(size)
        ab = _tracebuffer.create_agg_buffer(f.fileno(), name)
    return AggBuffer(ab, filename)


def open_agg_buffer(filename: str, size=DEFAULT_BUFFER_SIZE) -> AggBuffer:
    with open(filename, 'r+b', buffering=0) as f:
        f.truncate(size)
        ab = _tracebuffer.open_agg_buffer(f.fileno())
    return AggBuffer(ab, filename)


def encode_entry(key, value, Quantization) -> bytes:
    key_data = pickle.dumps(key)
    return _tracebuffer.encode_entry(key_data, value, Quantization)


# We skip the wrapper function as it adds about 40ns overhead and this is used
# in the hot path.
encode_value = _tracebuffer.encode_value

decode_value = _tracebuffer.decode_value
