import argparse
import atexit
import enum
import os
import socket
import subprocess
import sys

import pymontrace.attacher
from pymontrace import tracer
from pymontrace.tracer import (
    CommsFile, TraceState, convert_probe_filter, create_and_bind_socket,
    decode_and_print_forever, decode_and_print_remaining, encode_script,
    format_bootstrap_snippet, format_untrace_snippet, to_remote_path,
    validate_script
)


# Getting the version from package metadata adds quite a bit of overhead
# so we only do it if requested.
class VersionAction(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        help = "print pymontrace's version"
        super().__init__(option_strings, dest, nargs=0, help=help)

    def _get_version(self):
        import importlib.metadata
        return importlib.metadata.version("pymontrace")

    def __call__(self, parser, namespace, values, option_string=None):
        print(self._get_version())
        sys.exit(0)


parser = argparse.ArgumentParser(
    prog='pymontrace',
    description=(
        'Attaches to a running python program, or starts one, and injects '
        'debugging statements into selected probe sites.'
    ),
    allow_abbrev=False,
)

parser.add_argument('--version', action=VersionAction)
target_group = parser.add_argument_group('target selection')
target_group_alts = target_group.add_mutually_exclusive_group(required=True)
target_group_alts.add_argument(
    '-c', dest='pyprog',
    help=(
        "a python script to run and trace, including any arguments "
        "e.g. 'some_script.py \"one arg\" another'"
    ),
)
target_group_alts.add_argument(
    '-p', dest='pid', type=int,
    help='pid of a python process to attach to',
)
# used internally for handling -c',
target_group_alts.add_argument(
    '-X', dest='subproc',
    help=argparse.SUPPRESS,
)

action_group = parser.add_argument_group('action')
action_group_alts = action_group.add_mutually_exclusive_group(required=True)
action_group_alts.add_argument(
    '-e', dest='prog_text', type=str,
    help="pymontrace program text e.g. 'line:*script.py:13 {{ print(ctx.a, ctx.b) }}'",
)
action_group_alts.add_argument(
    '-l', dest='probe_filter', type=str,
    help=(
        "list available probe sites, takes a probe spec as a filter "
        "e.g. 'func:threading.*:start'"
    )
)
# If/when we allow script files
#
# action_group_alts.add_argument(
#     'script',
#     type=argparse.FileType('r'),
#     nargs='?',
#     help='a pymontrace script file'
# )


def force_unlink(path):
    try:
        os.unlink(path)
    except Exception:
        pass


class EndReason(enum.Enum):
    DISCONNECTED = enum.auto()
    EXITED = enum.auto()
    ENDED_EARLY = enum.auto()
    INTERRUPTED = enum.auto()


def receive_and_print_until_interrupted(
    pid: int, s: socket.socket, tracestate: TraceState
) -> EndReason:
    print('Probes installed. Hit CTRL-C to end...', file=sys.stderr)
    try:
        outcome = decode_and_print_forever(pid, s, tracestate)
        if outcome == tracer.DecodeEndReason.DISCONNECTED:
            print('Target disconnected.', file=sys.stderr)
            return EndReason.DISCONNECTED
        elif outcome == tracer.DecodeEndReason.EXITED:
            return EndReason.EXITED
        elif outcome == tracer.DecodeEndReason.ENDED_EARLY:
            return EndReason.ENDED_EARLY
        else:
            tracer.assert_never(outcome)
    except KeyboardInterrupt:
        return EndReason.INTERRUPTED


class PIDState(enum.Enum):
    GONE = enum.auto()
    STILL_THERE = enum.auto()


def wait_till_gone(pid: int, timeout=1.0) -> PIDState:
    try:
        exitstatus = pymontrace.attacher.reap_process(pid, int(timeout * 1000))
        print(f'Target exited with status {exitstatus}.', file=sys.stderr)
        return PIDState.GONE
    except TimeoutError:
        os.kill(pid, 0)  # A kind of assert
        return PIDState.STILL_THERE
    except ProcessLookupError:
        return PIDState.GONE
    except pymontrace.attacher.SignalledError as e:
        signum, desc = e.args
        print(f'Target killed by signal: {desc} ({signum})')
        return PIDState.GONE


def tracepid(pid: int, encoded_script: bytes):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        parser.error(f"no such process: {pid}")

    tracer.install_signal_handler()

    site_extension = tracer.install_pymontrace(pid)

    comms = CommsFile(pid)
    atexit.register(force_unlink, comms.localpath)

    with create_and_bind_socket(comms, pid) as ss:
        # requires sudo on mac
        pymontrace.attacher.attach_and_exec(
            pid,
            format_bootstrap_snippet(
                encoded_script, comms.remotepath,
                to_remote_path(pid, site_extension.name),
            ),
        )

        ss.settimeout(1.0)
        s, _ = ss.accept()
        # TODO: verify the connected party is pid
        os.unlink(comms.localpath)

        tracestate = TraceState()

        outcome = receive_and_print_until_interrupted(pid, s, tracestate)
        if (outcome == EndReason.INTERRUPTED
                or wait_till_gone(pid) == PIDState.STILL_THERE):
            print('Removing probes...', file=sys.stderr)
            # BUG: this may hang if end probes send too much data
            pymontrace.attacher.attach_and_exec(
                pid,
                format_untrace_snippet(),
            )
        decode_and_print_remaining(pid, s, tracestate)


def subprocess_entry(progpath, encoded_script: bytes):
    import runpy
    import shlex
    import time

    from pymontrace.tracee import connect, remote, settrace, unsettrace

    sys.argv = shlex.split(progpath)

    comm_file = CommsFile(os.getpid()).remotepath
    while not os.path.exists(comm_file):
        time.sleep(0.1)
    connect(comm_file)

    # Avoid code between settrace and starting the target program
    settrace(encoded_script)
    try:
        runpy.run_path(sys.argv[0], run_name='__main__')
    except KeyboardInterrupt:
        pass
    finally:
        unsettrace(preclose=remote.notify_exit)


def tracesubprocess(progpath: str, prog_text):
    p = subprocess.Popen(
        [sys.executable, '-m', 'pymontrace', '-X', progpath, '-e', prog_text]
    )

    comms = CommsFile(p.pid)
    atexit.register(force_unlink, comms.localpath)

    with create_and_bind_socket(comms, p.pid) as ss:
        s, _ = ss.accept()
        os.unlink(comms.localpath)

        tracestate = TraceState()
        outcome = receive_and_print_until_interrupted(p.pid, s, tracestate)
        # The child will also have had a SIGINT at this point as it's
        # in the same terminal group. So should have ended unless it's
        # installed its own signal handlers.
        decode_and_print_remaining(p.pid, s, tracestate)

        if outcome == EndReason.ENDED_EARLY:
            # User included an [pmt.]exit() call in their script
            # We own the subprocess - if the tracing stops, we kill this
            # patient to avoid an orphan.
            p.terminate()


def cli_main():
    args = parser.parse_args()

    if args.probe_filter:
        try:
            args.prog_text = convert_probe_filter(args.probe_filter)
        except Exception as e:
            parser.error(str(e))

    try:
        validate_script(args.prog_text)
    except Exception as e:
        parser.error(str(e))

    if args.pyprog:
        tracesubprocess(args.pyprog, args.prog_text)
    elif args.subproc:
        subprocess_entry(args.subproc, encode_script(args.prog_text))
    elif args.pid:
        tracepid(args.pid, encode_script(args.prog_text))
    else:
        parser.error("one of -p or -c required")


if __name__ == '__main__':
    cli_main()
