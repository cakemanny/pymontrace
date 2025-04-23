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
from typing import Literal, NoReturn, Union, Sequence

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
            self.regex = re.compile('^' + path.replace('*', '.*') + '$')

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

        star_count = sum(map(lambda c: c == '*', qpath))
        dot_count = sum(map(lambda c: c == '.', qpath))

        self.name = ""
        # Example: *.foo
        self.is_name_match = False
        if qpath.startswith('*.') and star_count == 1 and dot_count == 1:
            self.is_name_match = True
            self.name = qpath[2:]

        # Example: *.bar.foo
        self.is_suffix_path = False
        self.suff_module: list[str] = []
        if qpath.startswith('*.') and star_count == 1 and dot_count > 1:
            self.is_suffix_path = True
            *self.suff_module, self.name = qpath[2:].split('.')

        self.isregex = False
        if star_count > 0 and not self.is_name_match and not self.is_suffix_path:
            self.isregex = True
            self.regex = re.compile(
                '^' + qpath.replace('.', '\\.').replace('*', '.*') + '$'
            )

    @staticmethod
    def _faux_mod_path(file_path: str) -> list[str]:
        assert file_path.endswith(".py"), f"not endswith .py: {file_path!r}"
        parts = file_path.split('/')
        if parts[0] == '':
            parts = parts[1:]
        if parts[-1] == '__init__.py':
            return parts[:-1]
        # foo.py -> foo
        parts[-1] = parts[-1][:-3]
        return parts

    def matches(self, co_name: str, co_filename: str) -> bool:
        if self.is_name_match:
            return co_name == self.name

        # TODO: do something with '<module>' style filenames

        if self.is_suffix_path:
            if co_name != self.name:
                return False
            mod_path = self._faux_mod_path(co_filename)
            return self.suff_module == mod_path[-len(self.suff_module):]

        # TODO: this could make relpaths from sys.path
        mod_path = self._faux_mod_path(co_filename)
        faux_func_path = '.'.join(mod_path + [co_name])

        if self.isregex:
            return bool(self.regex.match(faux_func_path))

        return False


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

    vars = SimpleNamespace()

    _end_actions: list[tuple[PymontraceProbe, CodeType, str]] = []

    @staticmethod
    def _reset():
        pmt._end_actions = []
        pmt.vars = SimpleNamespace()


def safe_eval(action: CodeType, frame: FrameType, snippet: str):
    try:
        eval(action, {**frame.f_globals}, {
            **frame.f_locals,
            'pmt': pmt,
        })
    except Exception:
        _handle_eval_error(snippet)


def safe_eval_no_frame(action: CodeType, snippet: str):
    try:
        eval(action, None, {'pmt': pmt})
    except Exception:
        _handle_eval_error(snippet)


def _handle_eval_error(snippet: str) -> None:
    buf = io.StringIO()
    print('Probe action failed', file=buf)
    traceback.print_exc(file=buf)
    print(textwrap.indent(snippet, 4 * ' '), file=buf)
    pmt.print(buf.getvalue(), end='', file=sys.stderr)


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

    def make_local_handler(probe, action, snippet):
        if isinstance(probe, LineProbe):
            def handle_local(frame, event, _arg):
                if event != 'line' or probe.lineno != frame.f_lineno:
                    return handle_local
                safe_eval(action, frame, snippet)
                return None

        elif isinstance(probe, FuncProbe) and probe.site == 'return':
            # BUG: Both this event and 'exception' fire during an
            # exception
            def handle_local(frame, event, _arg):
                if event == 'return':
                    safe_eval(action, frame, snippet)
                    return None
                return handle_local

        elif isinstance(probe, FuncProbe) and probe.site == 'unwind':
            def handle_local(frame, event, _arg):
                if event == 'exception':
                    safe_eval(action, frame, snippet)
                    return None
                return handle_local

        else:
            def handle_local(frame, event, _arg):
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
        def handle_call(frame: FrameType, event, arg):
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
        def handle_call(frame: FrameType, event, arg):
            local_handlers = []
            for probe, action, snippet, local_handler in probes_and_handlers:
                assert isinstance(probe, FuncProbe)
                # first just entry
                if probe.site in ('start', 'return', 'unwind') and probe.matches(
                    frame.f_code.co_name, frame.f_code.co_filename
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

    def handle_call(frame: FrameType, event, arg):
        # TODO: have a list of possible probes to push into
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
                if probe.matches(
                    frame.f_code.co_name, frame.f_code.co_filename
                ):
                    safe_eval(action, frame, snippet)
            elif isinstance(probe, FuncProbe) and probe.site in ('return', 'unwind'):
                if probe.matches(
                    frame.f_code.co_name, frame.f_code.co_filename
                ):
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
            def handle_(probes, nodisable=False):
                def handle(code: CodeType, arg1, arg2=None):
                    for (probe, action, snippet) in probes:
                        if not probe.matches(code.co_name, code.co_filename):
                            continue
                        if ((cur_frame := inspect.currentframe()) is None
                                or (frame := cur_frame.f_back) is None):
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

        pmt._end_actions = [
            (probe, action, snippet)
            for (probe, action, snippet) in pmt_probes
            if probe.is_end
        ]
        for (probe, action, snippet) in pmt_probes:
            if probe.is_begin:
                safe_eval_no_frame(action, snippet)
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
        pmt._reset()
        remote.close()
    except Exception:
        print(f'{__name__}.unsettrace failed', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
