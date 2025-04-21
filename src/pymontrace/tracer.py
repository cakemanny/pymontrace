import inspect
import os
import pathlib
import re
import shutil
import signal
import socket
import struct
import sys
import textwrap
import threading
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from typing import NoReturn

from pymontrace import _darwin
from pymontrace import attacher
from pymontrace.tracee import PROBES_BY_NAME


# Replace with typing.assert_never after 3.11
def assert_never(arg: NoReturn) -> NoReturn:
    raise AssertionError(f"assert_never: got {arg!r}")


def parse_script(script_text: str):
    # In here we use i for "input"

    class ParseError(Exception):
        def __init__(self, message) -> None:
            super().__init__(message)
            self.message = message

    class ExpectError(ParseError):
        def __init__(self, expected, got=None) -> None:
            super().__init__(f'Expected {expected} got {got}')

    def expect(s):
        def f(i):
            if i.startswith(s):
                return s, i[len(s):]
            got = i if len(i) <= len(s) else f'{i[:len(s)]}...'
            raise ExpectError(s, got)
        return f

    def regex_parser(regex, desc=None):
        outer_desc = desc

        def parse_regex(i: str, desc=None):
            if m := re.match(regex, i):
                return m[0], i[len(m[0]):]
            assert desc is not None or outer_desc is not None, "regex_parser no desc"
            raise ExpectError(desc or outer_desc, got=i)
        return parse_regex

    def many(pred):
        def parsemany(i):
            c = 0
            while i[c:] and pred(i[c]):
                c += 1
            return i[:c], i[c:]
        return parsemany

    def manyone(pred, desc):
        thismany = many(pred)

        def parsemanyone(i):
            if not pred(i[:1]):
                raise ExpectError(desc, got=i)
            return thismany(i)
        return parsemanyone

    def whilenot(literal):
        def parseuntil(i):
            j = i
            c = 0
            while j and not j.startswith(literal):
                j = j[1:]
                c += 1
            if j.startswith(literal):
                return i[:c], i[c:]
            raise ParseError('Ending {literal!r} not found, got {i!r}')
        return parseuntil

    whitespace = many(str.isspace)
    nonempty_whitespace = manyone(str.isspace, 'whitespace')

    parse_colon = expect(':')
    parse_probe_name = regex_parser(r'[^:\s]+', 'probe name')
    parse_arg1 = regex_parser(r'[^:\s]*')
    parse_arg2 = regex_parser(r'[^:\s{]+')

    def parse_probe_spec(i):
        name, i = parse_probe_name(i)
        valid_probe_names = ('line', 'pymontrace', 'func')
        if name not in valid_probe_names:
            raise ParseError(
                f'Unknown probe {name!r}. '
                f'Valid probes are: {", ".join(valid_probe_names)}'
            )
        arg1_desc = {
            'line': 'file path',
            'pymontrace': 'nothing',
            'func': 'qualified function path (qpath)'
        }[name]
        arg2_desc = {
            'line': 'line number',
            'pymontrace': 'BEGIN or END',
            'func': 'func probe point'
        }[name]

        _, i = parse_colon(i)
        arg1, i = parse_arg1(i, arg1_desc)
        _, i = parse_colon(i)
        arg2, i = parse_arg2(i, arg2_desc)
        if name == 'line':
            _ = int(arg2)  # just validate
        elif name == 'pymontrace':
            if arg2 not in ('BEGIN', 'END'):
                raise ParseError(
                    f'Invalid probe point for pymontrace: {arg2}. '
                    'Valid pymontrace probe specs are: '
                    'pymontrace::BEGIN, pymontrace::END'
                )
        elif name == 'func':
            if any(not (c.isalnum() or c in '*._') for c in arg1):
                raise ParseError(f'Invalid qpath glob: {arg1!r}')
            if arg2 not in ('start', 'yield', 'resume', 'return', 'unwind'):
                raise ParseError(f'Invalid func probe point {arg2!r}')
        else:
            assert_never(name)
        return (name, arg1, arg2), i

    parse_action_start = expect('{{')
    parse_action_body = whilenot('}}')
    parse_action_end = expect('}}')

    def parse_probe_action(i: str):
        _, i = parse_action_start(i)
        inner, i = parse_action_body(i)
        _, i = parse_action_end(i)
        return inner, i

    probe_actions: list[tuple[tuple[str, str, str], str]] = []

    i = script_text
    _, i = whitespace(i)  # eat leading space
    while i:
        probespec, i = parse_probe_spec(i)
        _, i = nonempty_whitespace(i)
        action, i = parse_probe_action(i)

        # Should we check it's valid python? this may not be the target's
        # python...
        action = textwrap.dedent(action)
        compile(action, '<probeaction>', 'exec')

        probe_actions.append((probespec, action))
        _, i = whitespace(i)
    return probe_actions


def validate_script(script_text: str) -> str:
    """
    Raises an exception if the script text is invalid.
    Returns the script text if it's valid.
    """
    _ = parse_script(script_text)
    return script_text


def _encode_script(parsed_script) -> bytes:

    VERSION = 1
    result = bytearray()
    num_probes = len(parsed_script)
    result += struct.pack('=HH', VERSION, num_probes)

    for (probe_spec, action) in parsed_script:
        name, *args = probe_spec
        probe_id = PROBES_BY_NAME[name].id
        result += struct.pack('=BB', probe_id, len(args))
        for arg in args:
            result += arg.encode()
            result += b'\x00'
        result += action.encode()
        result += b'\x00'
    return bytes(result)


def encode_script(script_text: str) -> bytes:
    parsed = parse_script(script_text)
    return _encode_script(parsed)


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


def format_bootstrap_snippet(encoded_script: bytes, comm_file, site_extension):

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
        pymontrace.tracee.settrace({encoded_script!r})
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


def decode_and_print_forever(s: socket.socket, only_print=False):
    from pymontrace.tracee import Message

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
            elif kind == Message.THREADS and only_print:
                print(f'ignoring {kind=} during shutdown', file=sys.stderr)
            elif kind == Message.THREADS:
                count_threads = size // struct.calcsize('=Q')
                thread_ids = struct.unpack('=' + (count_threads * 'Q'), body)
                # This may not be the correct value if the target has forked
                pid = get_peer_pid(s)
                t = threading.Thread(target=settrace_in_threads,
                                     args=(pid, thread_ids), daemon=True)
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


def decode_and_print_remaining(s: socket.socket):
    # This should not block as the client should have disconnected
    decode_and_print_forever(s, only_print=True)
