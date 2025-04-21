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
    help='a python script to run and trace')
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
    help='Example: line:script.py:13 {{ print(a, b) }}',
    required=True
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
        print('Target disconnected.')
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
            )
        )

        # TODO: this needs a timeout
        s, _ = ss.accept()
        # TODO: verify the connected party is pid
        os.unlink(comms.localpath)

        receive_and_print_until_interrupted(s)
        pymontrace.attacher.attach_and_exec(
            pid,
            format_untrace_snippet()
        )
        decode_and_print_remaining(s)


def subprocess_entry(progpath, encoded_script: bytes):
    import runpy
    import time

    from pymontrace.tracee import settrace, connect

    comm_file = CommsFile(os.getpid()).remotepath
    while not os.path.exists(comm_file):
        time.sleep(1)
    connect(comm_file)
    settrace(encoded_script)

    runpy.run_path(progpath, run_name='__main__')


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
        p.terminate()
        # BUG: there's not a nice way to print and messages sent by
        # pymontrace::END


def cli_main():
    args = parser.parse_args()

    try:
        validate_script(args.prog_text)
    except Exception as e:
        print(str(e), file=sys.stderr)
        exit(1)

    if args.pyprog:
        tracesubprocess(args.pyprog, args.prog_text)
    elif args.subproc:
        subprocess_entry(args.subproc, encode_script(args.prog_text))
    elif args.pid:
        tracepid(args.pid, encode_script(args.prog_text))
    else:
        print('one of -p or -c required', file=sys.stderr)
        parser.print_usage(file=sys.stderr)
        exit(1)


if __name__ == '__main__':
    cli_main()
