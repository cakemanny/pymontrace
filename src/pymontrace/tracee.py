import inspect
import io
import os
import re
import sys
import textwrap
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


class pmt:

    # TODO: we need to come up with a message type and encoding format
    # so that we can buffer and also send other kinds of data
    comm_fh: Union[io.TextIOWrapper, None] = None

    print_buffer = []

    @staticmethod
    def print(*args):
        if pmt.comm_fh is not None:
            to_write = ' '.join(map(str, args)) + '\n'
            os.write(pmt.comm_fh.fileno(), to_write.encode())


def safe_eval(action: CodeType, frame: FrameType, snippet: str):
    try:
        eval(action, {**frame.f_globals}, {
            **frame.f_locals,
            'print': pmt.print,
        })
    except Exception:
        print('Probe action failed', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print(textwrap.indent(snippet, 4 * ''), file=sys.stderr)


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


# The function called inside the target to start tracing
def settrace(user_break, user_python_snippet, comm_file):

    if pmt.comm_fh is not None:
        # Maybe a previous settrace failed half-way through
        pmt.comm_fh.close()
    pmt.comm_fh = open(comm_file, 'w')
    pmt.comm_fh.reconfigure(write_through=True)

    try:
        user_python_obj = compile(user_python_snippet, '<pymontrace expr>', 'exec')
        probe = LineProbe(user_break[0], user_break[1])

        if sys.version_info < (3, 12):
            sys.settrace(create_event_handlers(
                probe, user_python_obj, user_python_snippet
            ))
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
            os.write(pmt.comm_fh.fileno(), buf.getvalue().encode())
        except Exception:
            print(f'{__name__}.settrace failed:', repr(e), file=sys.stderr)
        try:
            pmt.comm_fh.close()
            pmt.comm_fh = None
        except Exception:
            pass


def unsettrace():
    # This can fail if installing probes failed.
    try:
        if sys.version_info < (3, 12):
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
