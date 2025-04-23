import argparse
import atexit
import os
import socket
import subprocess
import sys

import pymontrace.attacher
from pymontrace import tracer
from pymontrace.tracer import (
    CommsFile, create_and_bind_socket, decode_and_print_forever,
    decode_and_print_remaining, encode_script, format_bootstrap_snippet,
    format_untrace_snippet, validate_script, to_remote_path
)

parser = argparse.ArgumentParser(prog='pymontrace')
parser.add_argument(
    '-c', dest='pyprog',
    help=(
        "a python script to run and trace, including any arguments "
        "e.g. 'some_script.py \"one arg\" another'"
    ),
)
parser.add_argument(
    '-p', dest='pid', type=int,
    help='pid of a python process to attach to',
)
# used internally for handling -c',
parser.add_argument(
    '-X', dest='subproc',
    help=argparse.SUPPRESS,
)
parser.add_argument(
    '-e', dest='prog_text', type=str,
    help="pymontrace program text e.g. 'line:*script.py:13 {{ pmt.print(a, b) }}'",
    required=True,
)


def force_unlink(path):
    try:
        os.unlink(path)
    except Exception:
        pass


def receive_and_print_until_interrupted(s: socket.socket):
    print('Probes installed. Hit CTRL-C to end...', file=sys.stderr)
    try:
        decode_and_print_forever(s)
        print('Target disconnected.', file=sys.stderr)
    except KeyboardInterrupt:
        pass
    print('Removing probes...', file=sys.stderr)


def tracepid(pid: int, encoded_script: bytes):
    os.kill(pid, 0)

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

        # TODO: this needs a timeout
        s, _ = ss.accept()
        # TODO: verify the connected party is pid
        os.unlink(comms.localpath)

        receive_and_print_until_interrupted(s)
        pymontrace.attacher.attach_and_exec(
            pid,
            format_untrace_snippet(),
        )
        decode_and_print_remaining(s)


def subprocess_entry(progpath, encoded_script: bytes):
    import runpy
    import time
    import shlex

    from pymontrace.tracee import connect, settrace, unsettrace

    comm_file = CommsFile(os.getpid()).remotepath
    while not os.path.exists(comm_file):
        time.sleep(1)
    connect(comm_file)
    settrace(encoded_script)

    sys.argv = shlex.split(progpath)

    try:
        runpy.run_path(sys.argv[0], run_name='__main__')
    except KeyboardInterrupt:
        pass
    finally:
        unsettrace()


def tracesubprocess(progpath: str, prog_text):
    p = subprocess.Popen(
        [sys.executable, '-m', 'pymontrace', '-X', progpath, '-e', prog_text]
    )

    comms = CommsFile(p.pid)
    atexit.register(force_unlink, comms.localpath)

    with create_and_bind_socket(comms, p.pid) as ss:
        s, _ = ss.accept()
        os.unlink(comms.localpath)

        receive_and_print_until_interrupted(s)
        # The child will also have had a SIGINT at this point as it's
        # in the same terminal group. So should have ended unless it's
        # installed its own signal handlers.
        decode_and_print_remaining(s)


def cli_main():
    args = parser.parse_args()

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
