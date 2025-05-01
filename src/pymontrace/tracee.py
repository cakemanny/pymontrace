"""
The module that is imported in the tracee.

This is a single large file to simplify injecting into the target (tracee).
All imports are from the standard library.
"""
import inspect
import io
import os
import re
import socket
import struct
import sys
import textwrap
import threading
import traceback
from collections import namedtuple
from types import CodeType, FrameType, SimpleNamespace
from typing import Any, Callable, Literal, NoReturn, Optional, Sequence, Union

TOOL_ID = sys.monitoring.DEBUGGER_ID if sys.version_info >= (3, 12) else 0


# Replace with typing.assert_never after 3.11
def assert_never(arg: NoReturn) -> NoReturn:
    raise AssertionError(f"assert_never: got {arg!r}")


class InvalidProbe:
    def __init__(self) -> None:
        raise IndexError('Invalid probe ID')


class LineProbe:
    def __init__(self, path: str, lineno: str) -> None:
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
            self.regex = re.compile(
                '^' + re.escape(path).replace('\\*', '.*') + '$'
            )

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


class PymontraceProbe:
    def __init__(self, _: str, hook: Literal['BEGIN', 'END']) -> None:
        self.is_begin = hook == 'BEGIN'
        self.is_end = hook == 'END'


_FUNC_PROBE_EVENT = Literal['start', 'yield', 'resume', 'return', 'unwind']


class FuncProbe:

    # Grouped by the shape of the sys.monitoring callback
    entry_sites = ('start', 'resume')
    return_sites = ('yield', 'return')
    unwind_sites = ('unwind')

    def __init__(self, qpath: str, site: _FUNC_PROBE_EVENT) -> None:
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
            self.regex = re.compile(
                '^' + re.escape(qpath).replace('\\*', '.*') + '$'
            )

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
    THREADS = 3  # Additional threads the tracer must attach to


class TracerRemote:

    comm_fh: Union[socket.socket, None] = None

    def __init__(self) -> None:
        self._lock = threading.RLock()

    @property
    def is_connected(self):
        # Not sure the lock is actually needed here if the GIL is still about
        with self._lock:
            return self.comm_fh is not None

    def connect(self, comm_file):
        if self.comm_fh is not None:
            # Maybe a previous settrace failed half-way through
            try:
                self.comm_fh.close()
            except Exception:
                pass
        self.comm_fh = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.comm_fh.connect(comm_file)

    def close(self):
        try:
            self.comm_fh.close()  # type: ignore  # we catch the exception
        except Exception:
            pass
        self.comm_fh = None

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
        unsettrace()
        self.close()

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


remote = TracerRemote()


class PMTError(Exception):
    """Represents a mistake in the use of pmt."""
    pass


class EvaluationError(PMTError):
    pass


class aggregation:
    COUNT = object()

    class Sum:
        def __init__(self, value):
            self.value = value

    class Max:
        def __init__(self, value):
            self.value = value

    class Min:
        def __init__(self, value):
            self.value = value


class agg:
    @staticmethod
    def count():
        return aggregation.COUNT

    @staticmethod
    def sum(value):
        return aggregation.Sum(value)

    @staticmethod
    def min(value):
        return aggregation.Min(value)

    @staticmethod
    def max(value):
        return aggregation.Max(value)


class VarNS(SimpleNamespace):

    def __setattr__(self, name: str, value, /) -> None:
        if value is aggregation.COUNT:
            # This would probably want / need to deal with threadlocalness /
            # contextness
            current = getattr(self, name, 0)
            object.__setattr__(self, name, current + 1)
        elif isinstance(value, aggregation.Sum):
            current = getattr(self, name, 0)
            object.__setattr__(self, name, current + value.value)
        elif isinstance(value, aggregation.Min):
            current = getattr(self, name, value.value)
            object.__setattr__(self, name, min(current, value.value))
        elif isinstance(value, aggregation.Max):
            current = getattr(self, name, value.value)
            object.__setattr__(self, name, max(current, value.value))
        else:
            object.__setattr__(self, name, value)


class PMTMap(dict):  # Should be collections.MutableMapping

    def __setitem__(self, key, value, /) -> None:
        if value is aggregation.COUNT:
            current = self.get(key, 0)
            return super().__setitem__(key, current + 1)
        elif isinstance(value, aggregation.Sum):
            current = self.get(key, 0)
            return super().__setitem__(key, current + value.value)
        elif isinstance(value, aggregation.Min):
            current = self.get(key, value.value)
            return super().__setitem__(key, min(current, value.value))
        elif isinstance(value, aggregation.Max):
            current = self.get(key, value.value)
            return super().__setitem__(key, max(current, value.value))
        else:
            return super().__setitem__(key, value)


class MapNS(SimpleNamespace):

    # Only happens on AttributeError
    def __getattr__(self, name):
        # At this point we'd create the buffer space
        # new_map = PMTMap()
        new_map = PMTMap()
        self.__setattr__(name, new_map)
        return new_map

    def __setattr__(self, name: str, value, /) -> None:
        if not isinstance(value, PMTMap):
            # ... The user is probably messing up some syntax..
            raise EvaluationError(
                f'cannot set attribute {name!r} on pmt.maps, '
                f'use pmt.maps[...] = ... or pmt.vars.{name} instead'
            )
        super().__setattr__(name, value)

    def __getitem__(self, key):
        # A default map. We use a name that's not possible in python
        # to avoid possible conflicts
        return getattr(self, '@')[key]

    def __setitem__(self, key, value, /) -> None:
        return getattr(self, '@').__setitem__(key, value)


class pmt:
    """
    pmt is a utility namespace of functions that may be useful for examining
    the system and returning data to the tracer.
    """

    @staticmethod
    def print(*args, **kwargs):
        if remote.is_connected:
            to_write = remote._encode_print(*args, **kwargs)
            remote.sendall(to_write)

    @staticmethod
    def exit(status=None):
        # FIXME: this is not re-entrant
        unsettrace()

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

    @staticmethod
    def printmaps():
        try:
            for name, mapp in vars(pmt.maps).items():
                pmt.print(name, "\n")
                kwidth, vwidth = 0, 0
                for k, v in mapp.items():
                    kwidth = max(kwidth, len(str(k)))
                    vwidth = max(vwidth, len(str(v)))
                for k, v in sorted(mapp.items(), key=lambda kv: kv[1]):
                    if isinstance(k, (int, str)):
                        pmt.print(f"  {k:{kwidth}}: {v:{vwidth}}")
                    else:
                        pmt.print(f"  {k!s:{kwidth}}: {v:{vwidth}}")
        except Exception:
            buf = io.StringIO()
            print(f'{__name__}.pmt.printmaps failed', file=buf)
            traceback.print_exc(file=buf)
            pmt.print(buf.getvalue(), end='', file=sys.stderr)

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


def safe_eval_no_frame(action: CodeType, snippet: str):
    try:
        noframepmt = pmt(frame=None)
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


def connect(comm_file):
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
                safe_eval_no_frame(action, snippet)

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


def unsettrace():
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
            safe_eval_no_frame(action, snippet)

        pmt.printmaps()

        pmt._reset()
        remote.close()
    except Exception:
        print(f'{__name__}.unsettrace failed', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
