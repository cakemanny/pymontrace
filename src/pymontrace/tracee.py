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
from typing import Union
from types import CodeType, FrameType

TOOL_ID = sys.monitoring.DEBUGGER_ID if sys.version_info >= (3, 12) else 0


class LineProbe:
    def __init__(self, path: str, lineno: int) -> None:
        self.path = path
        self.lineno = lineno

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


class Message:
    PRINT = 1
    ERROR = 2
    THREADS = 3  # Additional threads the tracer must attach to


class pmt:
    """
    pmt is a utility namespace of functions that may be useful for examining
    the system and returning data to the tracer.
    """

    # TODO: we should either use datagrams, or lock access to
    # this since we use it from multiple threads.
    comm_fh: Union[socket.socket, None] = None

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
    def print(*args, **kwargs):
        if pmt.comm_fh is not None:
            try:
                to_write = pmt._encode_print(*args, **kwargs)
                pmt.comm_fh.sendall(to_write)
            except BrokenPipeError:
                pmt._force_close()

    @staticmethod
    def _force_close():
        unsettrace()
        if pmt.comm_fh is not None:
            try:
                pmt.comm_fh.close()
            except Exception:
                pass
            pmt.comm_fh = None

    @staticmethod
    def _encode_threads(tids):
        count = len(tids)
        fmt = '=HH' + (count * 'Q')
        body_size = struct.calcsize((count * 'Q'))
        return struct.pack(fmt, Message.THREADS, body_size, *tids)

    @staticmethod
    def _notify_threads(tids):
        """
        Notify the tracer about additional threads that may need a
        settrace call.
        """
        if pmt.comm_fh is not None:
            try:
                to_write = pmt._encode_threads(tids)
                pmt.comm_fh.sendall(to_write)
            except BrokenPipeError:
                pmt._force_close()


def safe_eval(action: CodeType, frame: FrameType, snippet: str):
    try:
        eval(action, {**frame.f_globals}, {
            **frame.f_locals,
            'pmt': pmt,
        })
    except Exception:
        buf = io.StringIO()
        print('Probe action failed', file=buf)
        traceback.print_exc(file=buf)
        print(textwrap.indent(snippet, 4 * ''), file=buf)
        pmt.print(buf.getvalue(), end='', file=sys.stderr)


# Handlers for 3.11 and earlier
def create_event_handlers(probe: LineProbe, action: CodeType, snippet: str):

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

    def handle_local(frame, event, arg):
        if event != 'line' or probe.lineno != frame.f_lineno:
            return handle_local
        safe_eval(action, frame, snippet)
        return handle_local

    def handle_call(frame: FrameType, event, arg):
        if probe.lineno < frame.f_lineno:
            return None
        f_code = frame.f_code
        if not probe.matches_file(f_code.co_filename):
            return None
        if probe.lineno > f_code.co_firstlineno + num_lines(f_code):
            return None
        return handle_local

    return handle_call


def connect(comm_file):
    """
    Connect back to the tracer.
    Called by the tracer when attaching to the target.
    """
    if pmt.comm_fh is not None:
        # Maybe a previous settrace failed half-way through
        try:
            pmt.comm_fh.close()
        except Exception:
            pass
    pmt.comm_fh = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    pmt.comm_fh.connect(comm_file)


# The function called inside the target to start tracing
def settrace(user_break, user_python_snippet, is_initial=True):
    try:
        user_python_obj = compile(user_python_snippet, '<pymontrace expr>', 'exec')
        probe = LineProbe(user_break[0], user_break[1])

        if sys.version_info < (3, 12):
            event_handlers = create_event_handlers(
                probe, user_python_obj, user_python_snippet
            )
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
                    pmt._notify_threads(additional_tids)
        else:

            def handle_line(code: CodeType, line_number: int):
                if not probe.matches(code.co_filename, line_number):
                    return sys.monitoring.DISABLE
                if ((cur_frame := inspect.currentframe()) is None
                        or (frame := cur_frame.f_back) is None):
                    # TODO: warn about not being able to collect data
                    return
                safe_eval(user_python_obj, frame, user_python_snippet)

            sys.monitoring.use_tool_id(TOOL_ID, 'pymontrace')
            sys.monitoring.register_callback(
                TOOL_ID, sys.monitoring.events.LINE, handle_line
            )
            sys.monitoring.set_events(TOOL_ID, sys.monitoring.events.LINE)
    except Exception as e:
        try:
            buf = io.StringIO()
            print(f'{__name__}.settrace failed', file=buf)
            traceback.print_exc(file=buf)
            pmt.print(buf.getvalue(), end='', file=sys.stderr)
        except Exception:
            print(f'{__name__}.settrace failed:', repr(e), file=sys.stderr)
        try:
            pmt.comm_fh.close()  # type: ignore  # we catch the exception
            pmt.comm_fh = None
        except Exception:
            pass


def synctrace():
    """
    Called in each additional thread by the tracer.
    """
    # sys.settrace must be called in each thread that wants tracing
    if sys.version_info < (3, 10):
        sys.settrace(threading._trace_hook)
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
            sys.monitoring.register_callback(
                TOOL_ID, sys.monitoring.events.LINE, None
            )
            sys.monitoring.set_events(
                TOOL_ID, sys.monitoring.events.NO_EVENTS
            )
            sys.monitoring.free_tool_id(TOOL_ID)

        if pmt.comm_fh is not None:
            pmt.comm_fh.close()
            pmt.comm_fh = None
    except Exception:
        print(f'{__name__}.unsettrace failed', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
