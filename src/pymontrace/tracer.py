import inspect
import os
import pathlib
import shutil
import socket
import struct
import sys
import textwrap
from tempfile import TemporaryDirectory


def parse_probe(probe_spec):
    probe_name, probe_args = probe_spec.split(':', 1)
    if probe_name == 'line':
        filename, lineno = probe_args.split(':')
        return (probe_name, filename, int(lineno))
    else:
        raise ValueError('only "line" probe supported right now')


def install_pymontrace(pid: int) -> TemporaryDirectory:
    """
    In order that pymontrace can be used without prior installatation
    we prepare a module containing the tracee parts and extends
    """
    import pymontrace
    import pymontrace.tracee

    # Maybe there will be cases where checking for some TMPDIR is better.
    # but this seems to work so far.
    ptmpdir = '/tmp'
    if sys.platform == 'linux' and os.path.isdir('/proc/{pid}/root/tmp'):
        ptmpdir = '/proc/{pid}/root/tmp'

    tmpdir = TemporaryDirectory(dir=ptmpdir)
    # Would be nice to change this so the owner group is the target gid
    os.chmod(tmpdir.name, 0o755)
    moddir = pathlib.Path(tmpdir.name) / 'pymontrace'
    moddir.mkdir()

    for module in [pymontrace, pymontrace.tracee]:
        source_file = inspect.getsourcefile(module)
        if source_file is None:
            raise FileNotFoundError('failed to get source for module', module)

        shutil.copyfile(source_file, moddir / os.path.basename(source_file))

    return tmpdir


def to_remote_path(pid: int, path):
    proc_root = f'/proc/{pid}/root'
    if path.startswith(f'{proc_root}/'):
        return path[len(proc_root):]
    return path


def format_bootstrap_snippet(parsed_probe, action, comm_file, site_extension):
    user_break = parsed_probe[1:]

    import_snippet = textwrap.dedent(
        """
        import sys
        try:
            import pymontrace.tracee
        except Exception:
            sys.path.append('{0}')
            try:
                import pymontrace.tracee
            finally:
                sys.path.remove('{0}')
        """
    ).format(site_extension)

    settrace_snippet = textwrap.dedent(
        f"""
        pymontrace.tracee.settrace({user_break!r}, {action!r}, {comm_file!r})
        """
    )

    return '\n'.join([import_snippet, settrace_snippet])


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
        # TODO: We should probably add a random component with mktemp...
        self.remotepath = f'/tmp/pymontrace-{pid}'

        # Trailing slash needed otherwise it's the symbolic link
        pidroot = f'/proc/{pid}/root/'
        if (os.path.isdir(pidroot) and not os.path.samefile(pidroot, '/')):
            self.localpath = f'{pidroot}{self.remotepath[1:]}'
        else:
            self.localpath = self.remotepath


def create_and_bind_socket(comms: CommsFile) -> socket.socket:
    ss = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # TODO: only do this if we're not the owner of the process.
    # maybe it makes sense to set. (Linux: /proc/pid/loginuid, macos:
    # sysctl with KERN_PROC, KERN_PROC_UID , ...
    saved_umask = os.umask(0o000)
    ss.bind(comms.localpath)
    os.umask(saved_umask)
    ss.listen(0)
    return ss


def decode_and_print_forever(s: socket.socket):
    header_fmt = struct.Struct('HH')
    while True:
        header = s.recv(4)
        if header == b'':
            break
        (kind, size) = header_fmt.unpack(header)
        line = s.recv(size)
        out = (sys.stderr if kind == 2 else sys.stdout)
        out.write(line.decode())
