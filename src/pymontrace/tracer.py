from contextlib import contextmanager
import inspect
import os
import pathlib
import shutil
import signal
import socket
import struct
import sys
import textwrap
import threading
from tempfile import TemporaryDirectory

from pymontrace import _darwin
from pymontrace import attacher


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
    if sys.platform == 'linux' and os.path.isdir(f'/proc/{pid}/root/tmp'):
        ptmpdir = f'/proc/{pid}/root/tmp'

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
        pymontrace.tracee.connect({comm_file!r})
        pymontrace.tracee.settrace({user_break!r}, {action!r})
        """
    )

    return '\n'.join([import_snippet, settrace_snippet])


def format_additional_thread_snippet():
    return textwrap.dedent(
        """
        try:
            import pymontrace.tracee
            pymontrace.tracee.synctrace()
        except Exception:
            pass
        """
    )


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


def get_proc_euid(pid: int):
    if sys.platform == 'darwin':
        # A subprocess alternative would be:
        #   ps -o uid= -p PID
        return _darwin.get_euid(_darwin.kern_proc_info(pid))
    if sys.platform == 'linux':
        # Will this work if it's in a container ??
        with open(f'/proc/{pid}/status') as f:
            for line in f:
                if line.startswith('Uid:'):
                    # Linux: fs/proc/array.c (or
                    #        Documentation/filesystems/proc.rst)
                    # Uid:	uid	euid	suid	fsuid
                    return int(line.split('\t')[2])
            return None
    raise NotImplementedError


def is_own_process(pid: int):
    # euid is the one used to decide on access permissions.
    return get_proc_euid(pid) == os.geteuid()


@contextmanager
def set_umask(target_pid: int):
    # A future idea could be to get the gid of the target
    # and give their group group ownership.
    if not is_own_process(target_pid):
        saved_umask = os.umask(0o000)
        try:
            yield
        finally:
            os.umask(saved_umask)
    else:
        yield


def create_and_bind_socket(comms: CommsFile, pid: int) -> socket.socket:
    ss = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with set_umask(pid):
        ss.bind(comms.localpath)
    ss.listen(0)
    return ss


def get_peer_pid(s: socket.socket):
    if sys.platform == 'darwin':
        # See: sys/un.h
        SOL_LOCAL = 0
        LOCAL_PEERPID = 0x002
        peer_pid_buf = s.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4)
        return int.from_bytes(peer_pid_buf, sys.byteorder)
    if sys.platform == 'linux':
        ucred_buf = s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        (pid, uid, gid) = struct.unpack('iii', ucred_buf)
        return pid
    raise NotImplementedError


def settrace_in_threads(pid: int, thread_ids: 'tuple[int]'):
    try:
        attacher.exec_in_threads(
            pid, thread_ids, format_additional_thread_snippet()
        )
    except NotImplementedError:
        print(
            f'There are an additional {len(thread_ids)} threads '
            'that are not able to be traced', sys.stderr,
        )


def signal_handler(signo: int, frame):
    # We implement the default behaviour, i.e. terminating. But
    # we raise SystemExit so that finally blocks are run and atexit.
    raise SystemExit(128 + signo)


def install_signal_handler():
    for signo in [
            signal.SIGHUP,
            signal.SIGTERM,
            signal.SIGQUIT
    ]:
        signal.signal(signo, signal_handler)


def decode_and_print_forever(s: socket.socket):
    from pymontrace.tracee import Message

    install_signal_handler()

    t = None
    try:
        header_fmt = struct.Struct('=HH')
        while True:
            header = s.recv(header_fmt.size)
            if header == b'':
                break
            (kind, size) = header_fmt.unpack(header)
            body = s.recv(size)
            if kind in (Message.PRINT, Message.ERROR,):
                line = body
                out = (sys.stderr if kind == Message.ERROR else sys.stdout)
                out.write(line.decode())
            elif kind == Message.THREADS:
                count_threads = size // struct.calcsize('=Q')
                thread_ids = struct.unpack('=' + (count_threads * 'Q'), body)
                # This may not be the correct value if the target has forked
                pid = get_peer_pid(s)
                t = threading.Thread(target=settrace_in_threads,
                                     args=(pid, thread_ids))
                t.start()
            else:
                print('unknown message kind:', kind, file=sys.stderr)
    finally:
        # But maybe we need to kill it...
        if t is not None and t.ident:
            try:
                signal.pthread_kill(t.ident, signal.SIGINT)
            except ProcessLookupError:
                pass  # It may have finished.
            t.join()
