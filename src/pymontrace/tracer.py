import enum
import inspect
import io
import operator
import os
import pathlib
import re
import selectors
import shutil
import signal
import socket
import struct
import sys
import textwrap
import threading
import traceback
from contextlib import contextmanager
from dataclasses import dataclass
from tempfile import TemporaryDirectory
from typing import NoReturn, Union

from pymontrace import _darwin, attacher, tracebuffer
from pymontrace.tracebuffer import AggBuffer, TraceBuffer
from pymontrace.tracee import PROBES_BY_NAME, Quantization


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
    nonempty_whitespace = manyone(str.isspace, 'whitespace')  # noqa

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
        _, i = whitespace(i)
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


def convert_probe_filter(probe_filter: str) -> str:

    # This really ought to reuse the parsing logic above...

    parts = probe_filter.strip().split(':')

    if len(parts) > 3:
        raise ValueError('Too many probe parts. Expected at most 3')
    if len(parts) >= 3:
        # want to catch accidental mixup of -e and -l
        final_part = parts[2]
        if '{' in final_part:
            pf = probe_filter.strip()
            idx = pf.find('{', pf.find(':', pf.find(':') + 1) + 1)
            additional = pf + '\n' + (' ' * idx) + '^~'
            raise ValueError(
                "Unexpected '{' in probe filter. "
                "Did you mean to use the -e option instead of -l?"
                f"\n{additional}"
            )
    if ' ' in (pf := probe_filter.strip()):
        idx = pf.find(' ')
        additional = pf + '\n' + (' ' * idx) + '^~'
        raise ValueError(f"Unexpected space in probe filter.\n{additional}")

    if parts[0] not in ('func', 'line', 'pymontrace'):
        pf = probe_filter.strip()
        additional = pf + '\n' + '^' + ('~' * (len(parts[0]) - 1))
        raise ValueError(
            f'Unknown probe name {parts[0]!r}. '
            'Expected one of func, line, pymontrace.'
            f"\n{additional}"
        )

    args = ', '.join(f'{part!r}' for part in parts)
    # As two separate probes so the exit doesn't fail to happen on exception
    prog_text = 'pymontrace::BEGIN {{ printprobes(' + args + ') }} ' \
        + 'pymontrace::BEGIN {{ exit() }}'
    return prog_text


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
    import pymontrace._tracebuffer
    import pymontrace.tracebuffer
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

    for module in [pymontrace, pymontrace.tracee, pymontrace.tracebuffer]:
        source_file = inspect.getsourcefile(module)
        if source_file is None:
            raise FileNotFoundError('failed to get source for module', module)

        shutil.copyfile(source_file, moddir / os.path.basename(source_file))

    for module in [pymontrace._tracebuffer]:
        if module.__spec__ is None:
            raise RuntimeError(f'{module.__name__} missing __spec__ attribute')
        shared_object = module.__spec__.origin
        if shared_object is None:
            raise FileNotFoundError('failed to find shared object for module', module)
        shutil.copyfile(shared_object, moddir / os.path.basename(shared_object))

    return tmpdir


def to_remote_path(pid: int, path: str) -> str:
    proc_root = f'/proc/{pid}/root'
    if path.startswith(f'{proc_root}/'):
        return path[len(proc_root):]
    return path


def from_remote_path(pid: int, remote_path: str) -> str:
    """
    Converts a path that makes sense for the tracee to one that represents
    the same file from the perspective of the tracer
    """
    assert remote_path[0] == '/'
    # Trailing slash needed otherwise it's the symbolic link
    pidroot = f'/proc/{pid}/root/'
    if (os.path.isdir(pidroot) and not os.path.samefile(pidroot, '/')):
        return f'{pidroot}{remote_path[1:]}'
    else:
        return remote_path


def format_bootstrap_snippet(encoded_script: bytes, comm_file: str, site_extension: str):

    # Running settrace in a nested function does two things
    #  1. it keeps the locals dictionary clean in the injection site
    #  2. it fixes a bug that means that the top level of an interactive
    #  session could not be traced.
    return textwrap.dedent(
        f"""
        def _pymontrace_bootstrap():
            import sys
            do_unload = 'pymontrace.tracee' not in sys.modules
            try:
                import pymontrace.tracee
                pymontrace.tracee.do_unload = do_unload
            except Exception:
                sys.path.append('{site_extension}')
                try:
                    import pymontrace.tracee
                    pymontrace.tracee.do_unload = do_unload
                finally:
                    sys.path.remove('{site_extension}')
            pymontrace.tracee.connect({comm_file!r})
            pymontrace.tracee.settrace({encoded_script!r})
        _pymontrace_bootstrap()
        del _pymontrace_bootstrap
        """
    )


def format_additional_thread_snippet():
    return textwrap.dedent(
        """
        try:
            import pymontrace.tracee
            pymontrace.tracee.synctrace()
            del pymontrace
        except Exception:
            pass
        """
    )


def format_untrace_snippet():
    return textwrap.dedent(
        """
        import pymontrace.tracee
        pymontrace.tracee.unsettrace()
        if getattr(pymontrace.tracee, 'do_unload', False):
            del __import__('sys').modules['pymontrace.tracee']
            del __import__('sys').modules['pymontrace.tracebuffer']
            del __import__('sys').modules['pymontrace._tracebuffer']
            del __import__('sys').modules['pymontrace']
        del pymontrace
        """
    )


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
        self.localpath = from_remote_path(pid, self.remotepath)


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


signal_read, signal_write = socket.socketpair()


def signal_handler(signo: int, frame):
    try:
        signal_write.send(signo.to_bytes(1, sys.byteorder))
        # We close the write end of the pair so that we can exit it the
        # decode and print loop hangs due to a misbehaving tracee and the user
        # or OS sends a second "I'm impatient" signal
        signal_write.close()
    except OSError:
        # We implement the default behaviour, i.e. terminating. But
        # we raise SystemExit so that finally blocks are run and atexit.
        raise SystemExit(128 + signo)


def install_signal_handler():
    for signo in [
            signal.SIGINT,
            signal.SIGHUP,
            signal.SIGTERM,
            signal.SIGQUIT
    ]:
        signal.signal(signo, signal_handler)


class WaitResult(enum.Enum):
    READY = enum.auto()
    TIMEOUT = enum.auto()


def wait_till_ready_or_got_signal(
    s: socket.socket, sel: selectors.BaseSelector
) -> WaitResult:
    ready = sel.select(timeout=0.1)
    if len(ready) == 0:
        return WaitResult.TIMEOUT
    for key, _ in ready:
        if key.fileobj == signal_read:
            received = signal_read.recv(1)
            if received == b'':
                sel.unregister(signal_read)
                continue
            signo = int.from_bytes(received, sys.byteorder)
            if signo == signal.SIGINT:
                raise KeyboardInterrupt
            else:
                raise SystemExit(128 + signo)

        assert key.fileobj == s
    # If we make it out of that for loop it means s is ready
    return WaitResult.READY


class TraceState:
    def __init__(self):
        self.trace_buffers: list[TraceBuffer] = []
        self.agg_buffers: list[AggBuffer] = []

        # To not exhaust the tracee's memory,
        # periodically aggregation data is accumulated here in the tracer.
        self.chkptd_aggs = {}


def decode_trace_buffers_once(buffers: list[TraceBuffer]):
    from pymontrace.tracee import Message

    header_fmt = struct.Struct('=HH')

    for buf in buffers:
        data = buf.read()
        while data != b'':
            (kind, size) = header_fmt.unpack_from(data)
            offset = header_fmt.size
            body = data[offset:offset + size]
            data = data[offset + size:]
            if kind in (Message.PRINT, Message.ERROR,):
                line = body
                out = (sys.stderr if kind == Message.ERROR else sys.stdout)
                out.write(line.decode())
            else:
                print(f'unexpected data in trace buffer: {kind=}', file=sys.stderr)


def accumulate_func(agg_op: int):
    from pymontrace.tracee import AggOp

    if agg_op == AggOp.NONE:
        return lambda _, v2: v2
    elif agg_op == AggOp.COUNT:
        return operator.add
    elif agg_op == AggOp.SUM:
        return operator.add
    elif agg_op == AggOp.MAX:
        return max
    elif agg_op == AggOp.MIN:
        return min
    elif agg_op == AggOp.QUANTIZE:
        return operator.add
    raise ValueError(f'invalid agg_op: {agg_op}')


def read_records(agg_buffer: AggBuffer, epoch: Union[int, None] = None):

    f = io.BytesIO(agg_buffer.readall(epoch))

    while True:
        key_len_bytes = f.read(4)
        if len(key_len_bytes) < 4:
            break
        length = int.from_bytes(key_len_bytes, sys.byteorder)
        if length == 0:
            break
        key_bytes = f.read(length)
        if len(key_bytes) < length:
            break

        value_len_bytes = f.read(4)

        if len(value_len_bytes) < 4:
            break
        value_len = int.from_bytes(value_len_bytes, sys.byteorder)
        if value_len == 0:
            break
        value_bytes = f.read(value_len)
        if len(value_bytes) < value_len:
            break

        yield key_len_bytes + key_bytes + value_len_bytes + value_bytes


def accumulate_buffer(buffer: AggBuffer, epoch: int, ts: TraceState):
    from pymontrace.tracee import PMTMap

    accumulated = ts.chkptd_aggs.setdefault(buffer.name, {})

    agg_op = buffer.agg_op
    accumulate = accumulate_func(agg_op)

    for record_bytes in read_records(buffer, epoch=epoch):
        key, value = PMTMap._decode(record_bytes)
        if key in accumulated:
            existing = accumulated[key]
            accumulated[key] = accumulate(existing, value)
        else:
            accumulated[key] = value


def switch_aggregation_buffers(ts: TraceState):

    for buffer in ts.agg_buffers:

        # First check if the active buffer has been written to
        # (otherwise it's not really active).
        active = buffer.epoch
        if buffer.written(active) == 0:
            continue

        which = buffer.epoch - 1
        accumulate_buffer(buffer, which, ts)
        buffer.switch()


class DecodeEndReason(enum.Enum):
    DISCONNECTED = enum.auto()
    EXITED = enum.auto()
    ENDED_EARLY = enum.auto()


def decode_and_print_forever(
    pid: int, s: socket.socket, ts: TraceState, *, only_print=False
):
    from pymontrace.tracee import Message
    EVENT_READ = selectors.EVENT_READ

    sel = selectors.DefaultSelector()
    sel.register(signal_read, EVENT_READ)
    sel.register(s, EVENT_READ)

    t = None
    try:
        header_fmt = struct.Struct('=HH')
        while True:
            # We check for signals between message receipt so that s remains
            # in a good state to read final shutdown messages (e.g. from
            # the pymontrace::END probe)
            if wait_till_ready_or_got_signal(s, sel) == WaitResult.TIMEOUT:
                decode_trace_buffers_once(ts.trace_buffers)
                switch_aggregation_buffers(ts)
                continue

            header = s.recv(header_fmt.size)
            if header == b'':
                return DecodeEndReason.DISCONNECTED
            (kind, size) = header_fmt.unpack(header)
            body = s.recv(size)

            if kind == Message.THREADS and only_print:
                print(f'ignoring {kind=} during shutdown', file=sys.stderr)
            elif kind == Message.THREADS:
                count_threads = size // struct.calcsize('=Q')
                thread_ids = struct.unpack('=' + (count_threads * 'Q'), body)
                t = threading.Thread(target=settrace_in_threads,
                                     args=(pid, thread_ids), daemon=True)
                t.start()
            elif kind == Message.EXIT:
                return DecodeEndReason.EXITED
            elif kind == Message.END_EARLY:
                return DecodeEndReason.ENDED_EARLY
            elif kind == Message.BUFFER:
                filepath = body.decode()
                localpath = from_remote_path(pid, filepath)
                ts.trace_buffers.append(tracebuffer.create(localpath))
                os.unlink(localpath)
            elif kind == Message.HEARTBEAT:
                decode_trace_buffers_once(ts.trace_buffers)
            elif kind == Message.AGG_BUFFER:
                filepath = body.decode()
                localpath = from_remote_path(pid, filepath)
                ts.agg_buffers.append(tracebuffer.open_agg_buffer(localpath))
                os.unlink(localpath)
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


def decode_and_print_remaining(pid: int, s: socket.socket, ts: TraceState):
    # This should not block as the client should have disconnected
    decode_and_print_forever(pid, s, ts, only_print=True)
    decode_trace_buffers_once(ts.trace_buffers)

    for agg_buffer in ts.agg_buffers:
        accumulate_buffer(agg_buffer, agg_buffer.epoch - 1, ts)
        accumulate_buffer(agg_buffer, agg_buffer.epoch, ts)
    print_maps(ts)


def print_maps(ts: TraceState):
    for name, mapp in ts.chkptd_aggs.items():
        try:
            print_map(name, mapp)
        except Exception:
            print(f"Failed to print map: {name}:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)


def print_map(name, mapp, out=sys.stdout):

    print(name, "\n", file=out)
    kwidth, vwidth = 0, 0
    for k, v in mapp.items():
        kwidth = max(kwidth, len(str(k)))
        vwidth = max(vwidth, len(str(v)))
    for k, v in sorted(mapp.items(), key=lambda kv: kv[1]):
        if isinstance(k, (int, str)):
            key_part = f"  {k:{kwidth}}:"
        else:
            key_part = f"  {k!s:{kwidth}}:"
        if isinstance(v, Quantization):
            value_part = f"\n{v}"
        else:
            value_part = f" {v:{vwidth}}"
        print(f"{key_part}{value_part}", file=out)


@dataclass
class QuantizationRow:
    value: int
    distribution: float
    count: int


def format_quantization(self: Quantization):
    q = self
    # We shamelessly attempt to mimic dtrace here
    total_count = sum([count for count in q.buckets])
    if total_count == 0:
        raise ValueError('empty quantization')

    first_to_print = min(
        (bucket - 1) for bucket, count in enumerate(q.buckets)
        if count > 0
    )
    first_to_print = max(first_to_print, 0)

    last_to_print = max(
        (bucket + 1) for bucket, count in enumerate(q.buckets)
        if count > 0
    )
    last_to_print = min(last_to_print, len(q.buckets) - 1)

    rows: list[QuantizationRow] = []
    for bucket, count in enumerate(q.buckets):
        if first_to_print <= bucket <= last_to_print:
            rows.append(
                QuantizationRow(
                    value=q.idx_value(bucket),  # todo,
                    distribution=(count / total_count),
                    count=count,
                )
            )

    lines = [
        "               value  ------------- Distribution ------------- count"
    ]
    for row in rows:
        parts = []
        parts.append(f"{row.value:20} |")
        parts.append('@' * round(row.distribution * 40))
        parts.append(' ' * round((1 - row.distribution) * 40))
        parts.append(f" {row.count}")
        lines.append("".join(parts))
    return "\n".join(lines)


# We adapt the Quantization here to avoid adding too much tracer related
# code into the tracee
Quantization.__str__ = format_quantization
