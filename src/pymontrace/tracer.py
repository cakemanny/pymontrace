import os


def parse_probe(probe_spec):
    probe_name, probe_args = probe_spec.split(':', 1)
    if probe_name == 'line':
        filename, lineno = probe_args.split(':')
        return (probe_name, filename, int(lineno))
    else:
        raise ValueError('only "line" probe supported right now')


def format_bootstrap_snippet(parsed_probe, action, comm_file):
    user_break = parsed_probe[1:]
    return ('import pymontrace.tracee; '
            f'pymontrace.tracee.settrace({user_break!r}, {action!r}, {comm_file!r})')


def format_untrace_snippet():
    return 'import pymontrace.tracee; pymontrace.tracee.unsettrace()'


class CommsFile:
    """
    Defines where the communication socket is bound. Primarily for Linux,
    where the target may have another root directory, we define `remotepath`
    for use inside the tracee, once attached. `localpath` is where the tracer
    will create the socket in it's own view of the filesystem.
    """
    def __init__(self, pid: int):
        self.remotepath = f'/tmp/pymontrace-{pid}'

        # Trailing slash needed otherwise it's the symbolic link
        pidroot = f'/proc/{pid}/root/'
        if (os.path.isdir(pidroot) and not os.path.samefile(pidroot, '/')):
            self.localpath = f'{pidroot}{self.remotepath[1:]}'
        else:
            self.localpath = self.remotepath
