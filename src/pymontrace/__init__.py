import os
import re
import sys
import textwrap
import traceback

TOOL_ID = sys.monitoring.DEBUGGER_ID


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
        if self.is_path_endswith:
            return co_filename.endswith(self.pathend)
        if self.abs:
            to_match = co_filename
        else:
            to_match = os.path.relpath(co_filename)
        if self.isregex:
            return bool(self.regex.match(to_match))
        return to_match == self.path


# TODO: move this to some 'hook' module?
def settrace(user_break, user_python_snippet):
    # This bit would ideally be injected somehow
    if sys.version_info < (3, 12):
        def handle_events(frame, event, arg):
            print(frame, event, arg)
        sys.settrace(handle_events)
    else:
        import inspect
        from types import CodeType

        # An improvement might be to only register function start events
        # and then enable line events when we come across the right
        # file/function and disable otherwise. But that can come later.
        # maybe iterating over co_lines is more efficient than
        #   registering for all LINE events

        user_python_obj = compile(user_python_snippet, '<pymontrace expr>', 'exec')

        probe = LineProbe(user_break[0], user_break[1])

        def handle_line(code: CodeType, line_number: int):
            if probe.matches(code.co_filename, line_number):
                if ((cur_frame := inspect.currentframe()) is None
                        or (frame := cur_frame.f_back) is None):
                    # TODO: warn about not being able to collect data
                    return
                # TODO: add utility spaces to store aggregation data, etc
                try:
                    eval(user_python_obj, {**frame.f_globals}, {**frame.f_locals})
                except Exception:
                    print('Probe action failed', file=sys.stderr)
                    traceback.print_exc(file=sys.stderr)
                    print(textwrap.indent(user_python_snippet, 4 * ''), file=sys.stderr)

            else:
                return sys.monitoring.DISABLE
        sys.monitoring.use_tool_id(TOOL_ID, 'pymontrace')
        sys.monitoring.register_callback(
            TOOL_ID, sys.monitoring.events.LINE, handle_line
        )
        sys.monitoring.set_events(TOOL_ID, sys.monitoring.events.LINE)


def unsettrace():
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


def parse_probe(probe_spec):
    probe_name, probe_args = probe_spec.split(':', 1)
    if probe_name == 'line':
        filename, lineno = probe_args.split(':')
        return (probe_name, filename, int(lineno))
    else:
        # TODO: support function-entry/-exit probes
        raise ValueError('only "line" probe supported right now')


def format_bootstrap_snippet(parsed_probe, action):
    user_break = parsed_probe[1:]
    return ('import pymontrace; '
            f'pymontrace.settrace({user_break!r}, {action!r})')


def format_untrace_snippet():
    return 'import pymontrace; pymontrace.unsettrace()'
