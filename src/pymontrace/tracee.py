"""
The module that is imported in the tracee.

This is a single large file to simplify injecting into the target (tracee).
All imports are from the standard library.
"""
import array
import atexit
import inspect
import io
import os
import pickle
import re
import socket
import struct
import sys
import textwrap
import threading
import time
import traceback
from collections import abc, namedtuple
from types import CodeType, FrameType, SimpleNamespace
from typing import Any, Callable, Literal, NoReturn, Optional, Sequence, Union

from pymontrace import tracebuffer

TOOL_ID = sys.monitoring.DEBUGGER_ID if sys.version_info >= (3, 12) else 0


# Replace with typing.assert_never after 3.11
def assert_never(arg: NoReturn) -> NoReturn:
    raise AssertionError(f"assert_never: got {arg!r}")


def glob2re(glob_pattern: str):
    return re.compile('^' + re.escape(glob_pattern).replace('\\*', '.*') + '$')


class InvalidProbe:
    def __init__(self) -> None:
        raise IndexError('Invalid probe ID')


class LineProbe:
    def __init__(self, path: str, lineno: str) -> None:
        if path == '':
            path = '*'
        self.path = path
        self.lineno = int(lineno)

        self.abs = os.path.isabs(path)

        star_count = sum(map(lambda c: c == '*', path))
        self.is_path_endswith = path.startswith('*') and star_count == 1
        self.pathend = path
        if self.is_path_endswith:
            self.pathend = path[1:]
        # TODO: more glob optimizations

        self.isregex = False
        if star_count > 0 and not self.is_path_endswith:
            self.isregex = True
            self.regex = glob2re(path)

    def matches(self, co_filename: str, line_number: int):
        if line_number != self.lineno:
            return False
        return self.matches_file(co_filename)

    def matches_file(self, co_filename: str):
        if self.is_path_endswith:
            return co_filename.endswith(self.pathend)
        if self.abs:
            to_match = co_filename
        else:
            to_match = os.path.relpath(co_filename)
        if self.isregex:
            return bool(self.regex.match(to_match))
        return to_match == self.path

    def __eq__(self, value: object, /) -> bool:
        # Just implemented to help with tests
        if isinstance(value, LineProbe):
            return value.path == self.path and value.lineno == self.lineno
        return False

    @staticmethod
    def listsites(path='*', lineno='*'):
        if path == '':
            path = '*'
        if lineno == '':
            lineno = '*'
        # TODO: allow rangees for lineno
        curdir = os.path.abspath('.')
        probe = LineProbe(path, '0')
        for module in sys.modules.values():
            try:
                filepath = inspect.getfile(module)
            except (OSError, TypeError):
                continue
            if not probe.matches_file(filepath):
                continue
            if filepath.startswith(curdir):
                filepath = os.path.relpath(filepath)
            try:
                lines, start = inspect.getsourcelines(module)
                if start == 0:  # This might always be the case for modules
                    start = 1
                for i, line in enumerate(lines):
                    line = line.removesuffix('\n')
                    this_lineno = i + start
                    if lineno == '*' or str(this_lineno) == lineno:
                        yield f'line:{filepath}:{i + start} {line}'
            except OSError:
                pass


class PymontraceProbe:
    def __init__(self, _: str, hook: Literal['BEGIN', 'END']) -> None:
        self.is_begin = hook == 'BEGIN'
        self.is_end = hook == 'END'

    @staticmethod
    def listsites(unused='', hook='*'):
        if hook == '':
            hook = '*'
        if unused != '':
            return
        pattern = glob2re(hook)
        for h in ('BEGIN', 'END'):
            if pattern.match(h):
                yield f'pymontrace::{h}'


_FUNC_PROBE_EVENT = Literal['start', 'yield', 'resume', 'return', 'unwind']


class FuncProbe:

    # Grouped by the shape of the sys.monitoring callback
    entry_sites = ('start', 'resume')
    return_sites = ('yield', 'return')
    unwind_sites = ('unwind',)

    def __init__(self, qpath: str, site: _FUNC_PROBE_EVENT) -> None:
        if qpath == '':
            qpath = '*'
        for c in qpath:
            if not (c.isalnum() or c in '*._'):
                raise ValueError('invalid qpath glob: {qpath!r}')
        self.qpath = qpath
        self.site = site

        self.name = ""
        self.is_name_match = False
        self.is_star_match = False
        self.is_suffix_path = False
        self.suffix = ""
        self.isregex = False

        star_count = sum(map(lambda c: c == '*', qpath))
        dot_count = sum(map(lambda c: c == '.', qpath))

        if qpath == '*':
            self.is_star_match = True

        # Example: *.foo
        elif qpath.startswith('*.') and star_count == 1 and dot_count == 1:
            self.is_name_match = True
            self.name = qpath[2:]

        # Example: *.bar.foo
        elif qpath.startswith('*.') and star_count == 1 and dot_count > 1:
            self.is_suffix_path = True
            self.suffix = qpath[2:]
            self.name = self.suffix.split('.')[-1]

        elif star_count > 0:
            self.isregex = True
            self.regex = glob2re(qpath)

    def __repr__(self):
        return f'FuncProbe(qpath={self.qpath!r}, site={self.site!r})'

    def excludes(self, code: CodeType) -> bool:
        """fast path for when we don't have the frame yet"""
        if self.is_star_match:
            return False
        if self.is_name_match:
            return code.co_name != self.name
        return False

    def matches(self, frame: FrameType) -> bool:
        if self.is_star_match:
            return True
        if self.is_name_match:
            return frame.f_code.co_name == self.name

        if '__name__' not in frame.f_globals:
            # can happen if an eval/exec gets traced
            module_name = ''
            # It would be interesting to know if there are cases where
            # __name__ is not there but inspect.getmodulename can deduce
            # the name...
        else:
            module_name = frame.f_globals['__name__']

        co_name = frame.f_code.co_name

        if sys.version_info >= (3, 11):
            co_qualname = frame.f_code.co_qualname
            qpath = '.'.join(filter(bool, [module_name, co_qualname]))

            if self.is_suffix_path:
                if co_name != self.name:
                    return False
                return qpath.endswith(self.suffix)
        else:
            if self.is_suffix_path:
                if co_name != self.name:
                    return False
            # This is expensive, that's why we've split the is_suffix_path
            # condition into two parts.
            co_qualname = Frame.get_qualname(frame)
            qpath = '.'.join(filter(bool, [module_name, co_qualname]))
            if self.is_suffix_path:
                # Unsure if this should actually be a return if match
                return qpath.endswith(self.suffix)

        if self.isregex:
            return bool(self.regex.match(qpath))

        # make it simpler to trace simple scripts:
        if frame.f_globals.get('__name__') == '__main__':
            if self.qpath == co_qualname:
                return True

        return self.qpath == qpath

    @staticmethod
    def listsites(qpath='*', site='*'):
        if qpath == '':
            qpath = '*'
        if site == '':
            site = '*'
        funcsites = ('start', 'return', 'unwind')
        if sys.version_info < (3, 12):
            gensites = ()
        else:
            gensites = ('yield', 'resume')

        # it's a bit complicated to make fake frame objects and check matches
        # and we don't refactor to keep the real match code fast

        qp_regex = glob2re(qpath)
        if site != '*':
            site_regex = glob2re(site)
            funcsites = tuple(site for site in funcsites if site_regex.match(site))
            gensites = tuple(site for site in gensites if site_regex.match(site))

        for name, module in sys.modules.copy().items():
            for x, xvalue in vars(module).items():
                if inspect.isfunction(xvalue):
                    if inspect.isfunction(xvalue):
                        if qp_regex.match(qpath := f'{name}.{x}'):
                            for site in funcsites:
                                yield f"func:{qpath}:{site}"
                    if inspect.iscoroutinefunction(xvalue) \
                            or inspect.isgeneratorfunction(xvalue):
                        if qp_regex.match(qpath := f'{name}.{x}'):
                            for site in gensites:
                                yield f"func:{qpath}:{site}"
                elif inspect.isclass(o := xvalue):
                    # We use dir instead of vars to see base class methods
                    # on their subclasses too
                    for y in dir(o):
                        try:
                            field = getattr(o, y, None)
                        except Exception:
                            continue  # some descriptors try to import stuff
                        if field is None:
                            continue
                        if inspect.isfunction(field):
                            if qp_regex.match(qpath := f'{name}.{x}.{y}'):
                                for site in funcsites:
                                    yield f"func:{qpath}:{site}"
                        if inspect.iscoroutinefunction(field) \
                                or inspect.isgeneratorfunction(field):
                            if qp_regex.match(qpath := f'{name}.{x}.{y}'):
                                for site in gensites:
                                    yield f"func:{qpath}:{site}"


class Frame:

    # 3.9 and 3.10 only
    @staticmethod
    def get_qualname(frame: FrameType):
        co_name = frame.f_code.co_name
        if 'self' in frame.f_locals:
            classname = frame.f_locals['self'].__class__.__qualname__
            co_qualname = f"{classname}.{co_name}"
            return co_qualname

        # Is/was it a locally defined function?
        if (parent := frame.f_back) is not None:
            if (func := parent.f_locals.get(co_name)) is not None and \
                    inspect.isfunction(func):
                if frame.f_code is func.__code__:
                    return func.__qualname__
            if (func := parent.f_globals.get(co_name)) is not None and \
                    inspect.isfunction(func):
                if frame.f_code is func.__code__:
                    return func.__qualname__

            for v in parent.f_locals.values():
                if inspect.isfunction(func := v) and \
                        frame.f_code is func.__code__:
                    return func.__qualname__
            # There is another case where it might be a renamed
            # import but this is starting to get rather desperate
        # Fallback
        return co_name


ProbeDescriptor = namedtuple('ProbeDescriptor', ('id', 'name', 'construtor'))

PROBES = {
    0: ProbeDescriptor(0, 'invalid', InvalidProbe),
    1: ProbeDescriptor(1, 'line', LineProbe),
    2: ProbeDescriptor(2, 'pymontrace', PymontraceProbe),
    3: ProbeDescriptor(3, 'func', FuncProbe),
}
PROBES_BY_NAME = {
    descriptor.name: descriptor for descriptor in PROBES.values()
}
ValidProbe = Union[LineProbe, PymontraceProbe, FuncProbe]


def decode_pymontrace_program(encoded: bytes):

    def read_null_terminated_str(buf: bytes) -> tuple[str, bytes]:
        c = 0
        while buf[c] != 0:
            c += 1
        return buf[:c].decode(), buf[c + 1:]

    version, = struct.unpack_from('=H', encoded, offset=0)
    if version != 1:
        # PEF: Pymontrace Encoding Format
        raise ValueError(f'Unexpected PEF version: {version}')
    num_probes, = struct.unpack_from('=H', encoded, offset=2)

    probe_actions: list[tuple[ValidProbe, str]] = []
    remaining = encoded[4:]
    for _ in range(num_probes):
        probe_id, num_args = struct.unpack_from('=BB', remaining)
        remaining = remaining[2:]
        args = []
        for _ in range(num_args):
            arg, remaining = read_null_terminated_str(remaining)
            args.append(arg)
        action, remaining = read_null_terminated_str(remaining)

        ctor = PROBES[probe_id].construtor
        probe_actions.append(
            (ctor(*args), action)
        )
    assert len(remaining) == 0
    return probe_actions


class Message:
    PRINT = 1
    ERROR = 2
    THREADS = 3     # Additional threads the tracer must attach to
    EXIT = 4        # The tracee is exiting (atexit)
    END_EARLY = 5   # The tracing code called the pmt.exit function
    # MAPS = 6        # A new map file is available (TODO: clean up)
    BUFFER = 7      # A new trace buffer has been created
    HEARTBEAT = 8   # Sent to detect tracer death
    AGG_BUFFER = 9  # A new aggregation buffer has been created


class TracerRemote:

    comm_fh: Union[socket.socket, None] = None
    primary_buffer: Union[tracebuffer.TraceBuffer, None] = None

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.last_heartbeat = time.monotonic()
        self._agg_buffer_count = 0

    @property
    def is_connected(self):
        # Not sure the lock is actually needed here if the GIL is still about
        with self._lock:
            return self.comm_fh is not None

    def connect(self, comm_file: str):
        if self.comm_fh is not None:
            # Maybe a previous settrace failed half-way through
            try:
                self.comm_fh.close()
            except Exception:
                pass
        # TODO: once we don't send data anymore, switch to SOCK_DGRAM
        self.comm_fh = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.comm_fh.connect(comm_file)

    def close(self):
        with self._lock:
            self._close()

    def _close(self):
        try:
            self.comm_fh.close()  # type: ignore  # we catch the exception
        except Exception:
            pass
        self.comm_fh = None
        if self.primary_buffer is not None:
            self.primary_buffer.close()
            self.primary_buffer = None

    def sendall(self, data):
        # Probes may be installed in multiple threads. We lock to avoid
        # mixing messages from different threads onto the socket.
        with self._lock:
            if self.comm_fh is not None:
                try:
                    return self.comm_fh.sendall(data)
                except BrokenPipeError:
                    self._force_close()

    def _force_close(self):
        unsettrace()  # TODO: skip end actions... maybe
        self.close()

    def _heartbeat(self):
        if time.monotonic() - self.last_heartbeat > 1.0:
            self.send_heartbeat()
            self.last_heartbeat = time.monotonic()

    @staticmethod
    def _create_primary_buffer(comm_fh: socket.socket):
        # Should there be a separate one of these for each thread/cpu ?
        fn: str = comm_fh.getpeername() + '.buffer'
        assert fn.startswith('/'), f"{fn=}"
        return fn, tracebuffer.create(fn)

    def writeall(self, data):
        self._heartbeat()

        to_send = []
        with self._lock:
            if self.comm_fh is None:
                return
            if self.primary_buffer is None:
                fn, self.primary_buffer = self._create_primary_buffer(
                    self.comm_fh,
                )
                to_send.append(self._encode_buffer(fn))
            tb = self.primary_buffer
            tb.write(data)
            for msg in to_send:
                self.sendall(msg)

    def create_agg_buffer(self, name: str):
        if (comm_fh := self.comm_fh) is None:
            # can happen if disconnect happens during trace action execution
            raise RuntimeError('no remote')
        with self._lock:
            i = self._agg_buffer_count
            self._agg_buffer_count += 1
        fn: str = comm_fh.getpeername() + f'.map{i:03}'
        assert fn.startswith('/'), f"{fn=}"
        return tracebuffer.create_agg_buffer(name, fn)

    @staticmethod
    def _encode_print(*args, **kwargs):
        message_type = Message.PRINT
        if kwargs.get('file') == sys.stderr:
            message_type = Message.ERROR

        buf = io.StringIO()
        kwargs['file'] = buf
        print(*args, **kwargs)

        to_write = buf.getvalue().encode()
        return struct.pack('=HH', message_type, len(to_write)) + to_write

    @staticmethod
    def _encode_threads(tids):
        count = len(tids)
        fmt = '=HH' + (count * 'Q')
        body_size = struct.calcsize((count * 'Q'))
        return struct.pack(fmt, Message.THREADS, body_size, *tids)

    def notify_threads(self, tids):
        """
        Notify the tracer about additional threads that may need a
        settrace call.
        """
        to_write = self._encode_threads(tids)
        self.sendall(to_write)

    def _send_msg_no_body(self, msg: int):
        body_size = 0
        self.sendall(struct.pack('=HH', msg, body_size))

    def notify_exit(self):
        self._send_msg_no_body(Message.EXIT)

    def notify_end_early(self):
        self._send_msg_no_body(Message.END_EARLY)

    @staticmethod
    def _encode_buffer(filepath: str):
        to_write = filepath.encode()
        body_size = len(to_write)
        return struct.pack('=HH', Message.BUFFER, body_size) + to_write

    def send_heartbeat(self):
        self._send_msg_no_body(Message.HEARTBEAT)

    def notify_agg_buffer(self, filepath: str):
        to_write = filepath.encode()
        body_size = len(to_write)
        self.sendall(struct.pack('=HH', Message.AGG_BUFFER, body_size) + to_write)


remote = TracerRemote()


class PMTError(Exception):
    """Represents a mistake in the use of pmt."""
    pass


class EvaluationError(PMTError):
    pass


class AggOp:
    """Aggregation Operation"""
    NONE = 0
    COUNT = 1
    SUM = 2
    MAX = 3
    MIN = 4
    QUANTIZE = 5
    # How will this work if we add lquantize ??


class aggregation:
    class Base:
        op = AggOp.NONE

        def aggregate(self, current):
            raise NotImplementedError

    class Count(Base):
        op = AggOp.COUNT

        def aggregate(self, current: Optional[int]):
            return (current or 0) + 1

    class Sum(Base):
        op = AggOp.SUM

        def __init__(self, value):
            self.value = value

        def aggregate(self, current):
            return (current or 0) + self.value

    class Max(Base):
        op = AggOp.MAX

        def __init__(self, value):
            self.value = value

        def aggregate(self, current):
            return self.value if current is None else max(current, self.value)

    class Min(Base):
        op = AggOp.MIN

        def __init__(self, value):
            self.value = value

        def aggregate(self, current):
            return self.value if current is None else min(current, self.value)

    class Quantize(Base):
        op = AggOp.QUANTIZE

        def __init__(self, value):
            self.value = value

        def aggregate(self, current: Optional['Quantization']):
            quant = current or Quantization()
            quant.add(self.value)
            return quant


class agg:
    """
    A namespace of functions to be used in the actions.

    e.g. 'line:xxx.py:123 {{ maps[ctx.route] = agg.quantize(ctx.duration) }}'
    """
    @staticmethod
    def count():
        return aggregation.Count()

    @staticmethod
    def sum(value):
        return aggregation.Sum(value)

    @staticmethod
    def min(value):
        return aggregation.Min(value)

    @staticmethod
    def max(value):
        return aggregation.Max(value)

    @staticmethod
    def quantize(value):
        return aggregation.Quantize(value)


class Quantization:

    zero_idx = 64

    def __init__(self) -> None:
        self.buckets = array.array('Q', [0] * 128)

    # used in accumulation in tracer
    def __add__(self, other):
        if not isinstance(other, Quantization):
            raise TypeError
        result = Quantization()
        for i, (v0, v1) in enumerate(zip(self.buckets, other.buckets)):
            result.buckets[i] = v0 + v1
        return result

    def add(self, value):
        if not isinstance(value, (int, float)):
            raise TypeError(f"quantize: not int or float: {value!r}")
        # The highest power of two less than or equal to value

        value = int(value)
        bucket_idx = self.bucket_idx(value)
        if bucket_idx >= len(self.buckets):
            # perhaps introduce some kind of "scale" property ?
            raise ValueError('large number not yet quantizable: {value!r}')
        self.buckets[bucket_idx] += 1

    @classmethod
    def bucket_idx(cls, value: int) -> int:
        if value >= 0:
            return cls.zero_idx + value.bit_length()
        else:
            return cls.zero_idx - value.bit_length()

    @classmethod
    def idx_value(cls, bucket_idx: int) -> int:
        if bucket_idx == cls.zero_idx:
            return 0
        if bucket_idx < cls.zero_idx:
            return - 2**(-(1 + bucket_idx - cls.zero_idx))
        else:
            return 2**(bucket_idx - 1 - cls.zero_idx)


class VarNS(SimpleNamespace):

    def __setattr__(self, name: str, value, /) -> None:

        current = getattr(self, name, None)
        if isinstance(value, aggregation.Base):
            new = value.aggregate(current)
            object.__setattr__(self, name, new)
        else:
            object.__setattr__(self, name, value)


class PMTMap(abc.MutableMapping):
    def __init__(self, buffer: tracebuffer.AggBuffer) -> None:
        super().__init__()
        self.index: dict[Any, tuple[int, int]] = {}
        self.buffer = buffer
        self.agg_op = 0
        self.epoch = 2

    def __len__(self) -> int:
        return len(self.index)

    def __iter__(self):
        return iter(self.index)

    def _reset_index(self):
        self.epoch = self.buffer.epoch
        self.index = {}

    def __getitem__(self, key, /):
        with self.buffer:
            if self.epoch != self.buffer.epoch:
                self._reset_index()
            value, _ = self._getitem(key)
            return value

    _NO_DEFAULT = object()

    def _getitem(self, key, default=_NO_DEFAULT):
        try:
            offset, size = self.index[key]
        except KeyError:
            if default != self._NO_DEFAULT:
                return default, None
            raise
        data = self.buffer.read(offset, size)
        value = tracebuffer.decode_value(data, Quantization)
        return value, data

    @staticmethod
    def _encode(key, value) -> bytes:
        # pickle does not encode with a consistent size for same type
        # so we cannot use it for the value, which changes
        key_data = pickle.dumps(key)

        return (len(key_data).to_bytes(4, sys.byteorder)
                + key_data
                + PMTMap._encode_value(value))

    @staticmethod
    def _encode_value(value) -> bytes:
        value_data: bytes
        if isinstance(value, int):
            if value < 0:
                # we use `=` (standard) instead of '@' (native)
                # because we are anyway out of alignment
                value_data = b'q' + struct.pack('=q', value)
            else:
                value_data = b'Q' + struct.pack('=Q', value)
        elif isinstance(value, float):
            value_data = b'd' + struct.pack('=d', value)
        elif isinstance(value, Quantization):
            value_data = b'Y' + value.buckets.tobytes()
        else:
            raise TypeError(
                f'unsupported aggregation value type: {value.__class__.__name__}'
            )
        return (len(value_data).to_bytes(4, sys.byteorder)
                + value_data)

    @staticmethod
    def _decode(data: bytes) -> tuple:
        key_length = int.from_bytes(data[:4], byteorder=sys.byteorder)
        assert key_length <= len(data) - 4, f"{key_length} > {len(data[4:])}"

        key = pickle.loads(data[4:])  # ignores trailing
        value_length = int.from_bytes(data[4 + key_length:][:4], sys.byteorder)
        assert 4 + key_length + 4 + value_length == len(data), \
            f"4 + {key_length} + 4 + {value_length} != {len(data)}"

        value = tracebuffer.decode_value(data, Quantization)
        return key, value

    @staticmethod
    def _decode_value(data: bytes) -> Union[int, float, Quantization]:
        key_length = int.from_bytes(data[:4], sys.byteorder)
        value_data = data[8 + key_length:]
        if (prefix := value_data[:1]) in (b'qQd'):
            (value,) = struct.unpack('=' + prefix.decode(), value_data[1:])
        elif prefix == b'Y':
            value = object.__new__(Quantization)
            value.buckets = array.array('Q')
            value.buckets.frombytes(value_data[1:])
        else:
            raise ValueError(f'bad aggregation value with prefix {prefix}')
        return value

    def _setitem(self, key, value, old_data):
        if key in self.index:
            offset, size = self.index[key]
            new_value_data = tracebuffer.encode_value(value, Quantization)
            data = old_data[:-len(new_value_data)] + new_value_data
            self.buffer.update(data, offset, size)
        else:
            data = tracebuffer.encode_entry(key, value, Quantization)
            offset, size = self.buffer.write(data)
            self.index[key] = (offset, size)

    def __setitem__(self, key, value, /) -> None:
        with self.buffer:
            if self.epoch != self.buffer.epoch:
                self._reset_index()
            current, old_data = self._getitem(key, None)
            if isinstance(value, aggregation.Base):
                new = value.aggregate(current)
                self._setitem(key, new, old_data)
                if self.agg_op == 0:
                    self.buffer.agg_op = value.op
                    self.agg_op = value.op
            elif isinstance(value, (int, float, Quantization)):
                self._setitem(key, value, old_data)
            else:
                raise EvaluationError(
                    f'unsupported value type: {value.__class__.__name__}, '
                    'use an aggregation function such as agg.count() instead'
                )

    def __delitem__(self, key):
        # Maybe we could reset the value to 0
        raise NotImplementedError


class MapNS(SimpleNamespace):

    # Only happens on AttributeError
    def __getattr__(self, name: str):
        if name.startswith("__") or name == '_is_coroutine_marker':
            raise AttributeError(f"'MapNS' object has no attribute {name!r}")
        # At this point we create the buffer space
        buffer = remote.create_agg_buffer(name)
        new_map = PMTMap(buffer)
        self.__setattr__(name, new_map)
        remote.notify_agg_buffer(buffer.fn)
        return new_map

    def __setattr__(self, name: str, value, /) -> None:
        if not isinstance(value, PMTMap):
            # ... The user is probably messing up some syntax..
            raise EvaluationError(
                f'cannot set attribute {name!r} on maps, '
                f'use maps[...] = ... or vars.{name} instead'
            )
        super().__setattr__(name, value)

    def __getitem__(self, key):
        # A default map. We use a name that's not possible in python
        # to avoid possible conflicts
        return getattr(self, '@')[key]

    def __setitem__(self, key, value, /) -> None:
        return getattr(self, '@').__setitem__(key, value)

    def __delitem__(self, key):
        return getattr(self, '@').__delitem__(key)


class pmt:
    """
    pmt is a utility namespace of functions that may be useful for examining
    the system and returning data to the tracer.
    """

    @staticmethod
    def print(*args, **kwargs):
        if remote.is_connected:
            to_write = remote._encode_print(*args, **kwargs)
            remote.writeall(to_write)

    @staticmethod
    def exit(status=None):
        unsettrace(preclose=remote.notify_end_early())

    def __init__(self, frame: Optional[FrameType]):
        self._frame = frame
        self._frozen = True

    def funcname(self):
        if self._frame is None:
            return None
        return self._frame.f_code.co_name

    def qualname(self, Frame=Frame):
        frame = self._frame
        if frame is None:
            return None
        module_name = frame.f_globals.get('__name__')
        if sys.version_info < (3, 11):
            co_qualname = Frame.get_qualname(frame)
        else:
            co_qualname = frame.f_code.co_qualname
        if module_name:
            return f'{module_name}.{co_qualname}'
        return co_qualname

    def args(self):
        frame = self._frame
        if frame is None:
            return None
        f_code = frame.f_code
        num_args = (f_code.co_argcount + f_code.co_kwonlyargcount)
        result = {}
        for name in f_code.co_varnames[:num_args]:
            result[name] = frame.f_locals[name]
        return result

    def printprobes(self, probename, *args):
        # Used to handle the -l flag
        # ... could use PROBES_BY_NAME and/or could glob match the probename
        if probename == 'pymontrace':
            for probesite in PymontraceProbe.listsites(*args):
                pmt.print(probesite)
        elif probename == 'func':
            for probesite in FuncProbe.listsites(*args):
                pmt.print(probesite)
        elif probename == 'line':
            for probesite in LineProbe.listsites(*args):
                pmt.print(probesite)

    _end_actions: list[tuple[PymontraceProbe, CodeType, str]] = []

    vars = VarNS()
    maps = MapNS()

    @staticmethod
    def _reset():
        pmt._end_actions = []
        pmt.vars = VarNS()
        pmt.maps = MapNS()

    def __setattr__(self, name: str, value, /) -> None:
        # It's quite easy too accidentally assign to something here
        # instead of into pmt.vars. This should help.
        if getattr(self, "_frozen", False):
            raise EvaluationError(
                f'cannot set {name!r}, pmt is readonly, '
                'set your attribute on pmt.vars or pmt.maps instead'
            )
        return super().__setattr__(name, value)

    def _asdict(self):
        o = {}
        for k in (vars(self) | vars(pmt)):
            if not k.startswith("_"):
                # seems to be necessary in python 3.9 to access the
                # staticmethods through the instance ... :shrug:
                o[k] = getattr(self, k)
        return o


class ChainNS(SimpleNamespace):
    def __init__(self, level1, level2, /, **kwargs):
        self.__dict__.update(level1)
        self.__dict__.update(kwargs)
        self._level2 = level2

    def __getattr__(self, name: str):
        return getattr(self._level2, name)


def safe_eval(action: CodeType, frame: FrameType, snippet: str):
    try:
        framepmt = pmt(frame)
        globals_as_ns = SimpleNamespace(**frame.f_globals)
        eval(action, {
            'ctx': ChainNS(
                frame.f_locals,
                globals_as_ns,
                # to allow getting around shadowed variables
                globals=globals_as_ns,
            ),
            'pmt': framepmt,
            **framepmt._asdict(),
            'agg': agg,
        }, {})
    except Exception as e:
        _handle_eval_error(e, snippet, frame)


def safe_eval_no_frame(action: CodeType, snippet: str, exit):
    try:
        noframepmt = pmt(frame=None)
        object.__setattr__(noframepmt, 'exit', exit)
        eval(action, {
            'pmt': noframepmt,
            **noframepmt._asdict(),
            'agg': agg,
        }, {})
    except Exception as e:
        _handle_eval_error(e, snippet)


def _handle_eval_error(
    e: Exception, snippet: str, frame: Optional[FrameType] = None,
) -> None:
    buf = io.StringIO()
    print('Probe action failed:', file=buf)
    if isinstance(e, PMTError):
        if frame is not None:
            traceback.print_stack(frame, file=buf)
        print(f"{e.__class__.__name__}: {e}", file=buf)
    else:
        traceback.print_exc(file=buf)
    print(textwrap.indent(snippet, 4 * ' '), file=buf)
    pmt.print(buf.getvalue(), end='', file=sys.stderr)


TraceFunction = Callable[[FrameType, str, Any], Union['TraceFunction', None]]


# Handlers for 3.11 and earlier - TODO: should this be guarded?
def create_event_handlers(
    probe_actions: Sequence[tuple[Union[LineProbe, FuncProbe], CodeType, str]],
):

    if sys.version_info < (3, 10):
        # https://github.com/python/cpython/blob/3.12/Objects/lnotab_notes.txt
        def num_lines(f_code: CodeType):
            lineno = addr = 0
            it = iter(f_code.co_lnotab)
            for addr_incr in it:
                line_incr = next(it)
                addr += addr_incr
                if line_incr >= 0x80:
                    line_incr -= 0x100
                lineno += line_incr
            return lineno
    else:
        def num_lines(f_code: CodeType):
            lineno = f_code.co_firstlineno
            for (start, end, this_lineno) in f_code.co_lines():
                if this_lineno is not None:
                    lineno = max(lineno, this_lineno)
            return lineno - f_code.co_firstlineno

    def make_local_handler(probe, action: CodeType, snippet: str) -> TraceFunction:
        if isinstance(probe, LineProbe):
            def handle_local(frame, event, _arg) -> Optional[TraceFunction]:
                if event != 'line' or probe.lineno != frame.f_lineno:
                    return handle_local
                safe_eval(action, frame, snippet)
                return None

        elif isinstance(probe, FuncProbe) and probe.site == 'return':
            # BUG: Both this event and 'exception' fire during an
            # exception
            def handle_local(frame, event, _arg) -> Optional[TraceFunction]:
                if event == 'return':
                    safe_eval(action, frame, snippet)
                    return None
                return handle_local
            return handle_local

        elif isinstance(probe, FuncProbe) and probe.site == 'unwind':
            def handle_local(frame, event, _arg) -> Optional[TraceFunction]:
                if event == 'exception':
                    safe_eval(action, frame, snippet)
                    return None
                return handle_local
            return handle_local
        else:
            def handle_local(frame, event, _arg) -> Optional[TraceFunction]:
                return handle_local
            return handle_local
        return handle_local

    def combine_handlers(handlers):
        def handle(frame, event, arg):
            for h in handlers:
                result = h(frame, event, arg)
                if result is None:
                    return None
            return handle
        return handle

    count_line_probes = 0
    count_exit_probes = 0
    count_start_probes = 0
    for (probe, action, snippet) in probe_actions:
        if isinstance(probe, LineProbe):
            count_line_probes += 1
        elif isinstance(probe, FuncProbe) and probe.site == 'start':
            count_start_probes += 1
        elif isinstance(probe, FuncProbe) and probe.site in ('return', 'unwind'):
            count_exit_probes += 1

    # We allow that only one probe will match any given event
    probes_and_handlers = [
        (probe, action, snippet, make_local_handler(probe, action, snippet))
        for (probe, action, snippet) in probe_actions
    ]

    if count_line_probes > 0 and (count_start_probes == 0 and count_exit_probes == 0):
        def handle_call(frame: FrameType, event, arg) -> Union[TraceFunction, None]:
            for probe, action, snippet, local_handler in probes_and_handlers:
                assert isinstance(probe, LineProbe)
                if probe.lineno < frame.f_lineno:
                    continue
                f_code = frame.f_code
                if not probe.matches_file(f_code.co_filename):
                    continue
                if probe.lineno > f_code.co_firstlineno + num_lines(f_code):
                    continue
                return local_handler
            return None
        return handle_call

    if count_line_probes == 0:
        def handle_call(frame: FrameType, event, arg) -> Union[TraceFunction, None]:
            local_handlers = []
            for probe, action, snippet, local_handler in probes_and_handlers:
                assert isinstance(probe, FuncProbe)
                # first just entry
                if probe.site in ('start', 'return', 'unwind') and probe.matches(
                    frame
                ):
                    if probe.site == 'start':
                        safe_eval(action, frame, snippet)
                        continue
                    else:
                        # There are no line probes
                        frame.f_trace_lines = False
                        local_handlers.append(local_handler)
            if len(local_handlers) == 1:
                return local_handlers[0]
            if len(local_handlers) > 1:
                return combine_handlers(local_handlers)
            return None
        return handle_call

    def handle_call(frame: FrameType, event, arg) -> Union[TraceFunction, None]:
        local_handlers = []
        for probe, action, snippet, local_handler in probes_and_handlers:
            if isinstance(probe, LineProbe):
                if probe.lineno < frame.f_lineno:
                    continue
                f_code = frame.f_code
                if not probe.matches_file(f_code.co_filename):
                    continue
                if probe.lineno > f_code.co_firstlineno + num_lines(f_code):
                    continue
                local_handlers.append(local_handler)
            elif isinstance(probe, FuncProbe) and probe.site == 'start':
                if probe.matches(frame):
                    safe_eval(action, frame, snippet)
            elif isinstance(probe, FuncProbe) and probe.site in ('return', 'unwind'):
                if probe.matches(frame):
                    local_handlers.append(local_handler)
        if len(local_handlers) == 1:
            return local_handlers[0]
        if len(local_handlers) > 1:
            return combine_handlers(local_handlers)
        return None

    return handle_call


def connect(comm_file: str):
    """
    Connect back to the tracer.
    Tracer invokes this in the target when attaching to it.
    """
    remote.connect(comm_file)


if sys.version_info >= (3, 12):

    # We enumerate the ones we use so that it's easier to
    # unregister callbacks for them
    class events:
        LINE = sys.monitoring.events.LINE
        PY_START = sys.monitoring.events.PY_START
        PY_RESUME = sys.monitoring.events.PY_RESUME
        PY_YIELD = sys.monitoring.events.PY_YIELD
        PY_RETURN = sys.monitoring.events.PY_RETURN
        PY_UNWIND = sys.monitoring.events.PY_UNWIND

        @classmethod
        def all(cls):
            for k, v in cls.__dict__.items():
                if not k.startswith("_") and isinstance(v, int):
                    yield v


# The function called inside the target to start tracing
def settrace(encoded_program: bytes, is_initial=True):
    try:
        probe_actions = decode_pymontrace_program(encoded_program)

        pmt_probes: list[tuple[PymontraceProbe, CodeType, str]] = []
        line_probes: list[tuple[LineProbe, CodeType, str]] = []
        func_probes: list[tuple[FuncProbe, CodeType, str]] = []

        for probe, user_python_snippet in probe_actions:
            user_python_obj = compile(
                user_python_snippet, '<pymontrace expr>', 'exec'
            )
            # Will support more probes in future.
            assert isinstance(probe, (LineProbe, PymontraceProbe, FuncProbe)), \
                f"Bad probe type: {probe.__class__.__name__}"
            if isinstance(probe, LineProbe):
                line_probes.append((probe, user_python_obj, user_python_snippet))
            elif isinstance(probe, PymontraceProbe):
                pmt_probes.append((probe, user_python_obj, user_python_snippet))
            elif isinstance(probe, FuncProbe):
                func_probes.append((probe, user_python_obj, user_python_snippet))
            else:
                assert_never(probe)

        pmt._end_actions = [
            (probe, action, snippet)
            for (probe, action, snippet) in pmt_probes
            if probe.is_end
        ]
        for (probe, action, snippet) in pmt_probes:
            if probe.is_begin:
                safe_eval_no_frame(action, snippet, exit=early_exit)

        if sys.version_info < (3, 12):
            # TODO: handle func probes
            event_handlers = create_event_handlers(line_probes + func_probes)
            sys.settrace(event_handlers)
            if is_initial:
                threading.settrace(event_handlers)
                own_tid = threading.get_native_id()
                additional_tids = [
                    thread.native_id for thread in threading.enumerate()
                    if (thread.native_id != own_tid
                        and thread.native_id is not None)
                ]
                if additional_tids:
                    remote.notify_threads(additional_tids)
        else:

            def handle_line(code: CodeType, line_number: int):
                for (probe, action, snippet) in line_probes:
                    if not probe.matches(code.co_filename, line_number):
                        continue
                    if ((cur_frame := inspect.currentframe()) is None
                            or (frame := cur_frame.f_back) is None):
                        # TODO: warn about not being able to collect data
                        continue
                    safe_eval(action, frame, snippet)
                    return None
                return sys.monitoring.DISABLE

            start_probes = [p for p in func_probes if p[0].site == 'start']
            resume_probes = [p for p in func_probes if p[0].site == 'resume']
            yield_probes = [p for p in func_probes if p[0].site == 'yield']
            return_probes = [p for p in func_probes if p[0].site == 'return']
            unwind_probes = [p for p in func_probes if p[0].site == 'unwind']

            # For any func probe except unwind
            def handle_(
                probes: list[tuple[FuncProbe, CodeType, str]],
                nodisable=False,
            ):
                def handle(code: CodeType, arg1, arg2=None):
                    for (probe, action, snippet) in probes:
                        if probe.excludes(code):
                            continue
                        if ((cur_frame := inspect.currentframe()) is None
                                or (frame := cur_frame.f_back) is None):
                            continue
                        if not probe.matches(frame):
                            continue
                        safe_eval(action, frame, snippet)
                        return None
                    if nodisable:
                        return None
                    return sys.monitoring.DISABLE
                return handle

            sys.monitoring.use_tool_id(TOOL_ID, 'pymontrace')

            event_set: int = 0
            handlers = [
                (events.LINE, line_probes, handle_line),
                (events.PY_START, start_probes, handle_(start_probes)),
                (events.PY_RESUME, resume_probes, handle_(resume_probes)),
                (events.PY_YIELD, yield_probes, handle_(yield_probes)),
                (events.PY_RETURN, return_probes, handle_(return_probes)),
                (events.PY_UNWIND, unwind_probes, handle_(unwind_probes, nodisable=True)),
            ]
            for event, probes, handler in handlers:
                if len(probes) > 0:
                    sys.monitoring.register_callback(
                        TOOL_ID, event, handler
                    )
                    event_set |= event

            sys.monitoring.set_events(TOOL_ID, event_set)

        atexit.register(exithook)

    except Exception as e:
        try:
            buf = io.StringIO()
            print(f'{__name__}.settrace failed', file=buf)
            traceback.print_exc(file=buf)
            pmt.print(buf.getvalue(), end='', file=sys.stderr)
        except Exception:
            print(f'{__name__}.settrace failed:', repr(e), file=sys.stderr)
        remote.close()


def synctrace():
    """
    Called in each additional thread by the tracer.
    """
    # sys.settrace must be called in each thread that wants tracing
    if sys.version_info < (3, 10):
        sys.settrace(threading._trace_hook)  # type: ignore  # we're adults
    elif sys.version_info < (3, 12):
        sys.settrace(threading.gettrace())
    else:
        pass  # sys.monitoring should already have all threads covered.


def exithook():
    unsettrace(preclose=remote.notify_exit)


def unsettrace(preclose=None):
    atexit.unregister(exithook)
    # This can fail if installing probes failed.
    try:
        if sys.version_info < (3, 12):
            threading.settrace(None)  # type: ignore  # bug in typeshed.
            sys.settrace(None)
        else:
            for event in events.all():
                sys.monitoring.register_callback(
                    TOOL_ID, event, None
                )
            sys.monitoring.set_events(
                TOOL_ID, sys.monitoring.events.NO_EVENTS
            )
            sys.monitoring.free_tool_id(TOOL_ID)

        for (probe, action, snippet) in pmt._end_actions:
            assert probe.is_end
            safe_eval_no_frame(action, snippet, exit=null_exit)

        pmt._reset()
        if preclose is not None:
            preclose()
        remote.close()
    except Exception:
        print(f'{__name__}.unsettrace failed', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)


# An exit that can be called during BEGIN probes, before tracing has been
# installed.
def early_exit(status=None):
    remote.notify_end_early()
    remote.close()


# An exit that can be called during END probes. We ignore exit in END probes
def null_exit(status=None):
    pass
