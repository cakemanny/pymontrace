import argparse
import os
import socket
import struct
import subprocess
import sys

import pymontrace.attacher
from pymontrace import tracer
from pymontrace.tracer import (
    CommsFile, format_bootstrap_snippet, format_untrace_snippet, parse_probe,
    to_remote_path
)

parser = argparse.ArgumentParser(prog='pymontrace')
parser.add_argument(
    '-c', dest='pyprog',
    help='a python script to run and trace')
parser.add_argument(
    '-p', dest='pid',
    help='pid of a python process to attach to',
    type=int,
)
parser.add_argument(
    '-X', dest='subproc',
    help='used internal for handling -c')
parser.add_argument(
    'probe',
    type=parse_probe,
    help='Example: line:script.py:13')
parser.add_argument(
    'action',
    help='a python expression to evaluate each time the probe site is reached')


def tracepid(pid: int, probe, action: str):
    # ... maybe use an ExitStack to refactor

    site_extension = tracer.install_pymontrace(pid)

    comms = CommsFile(pid)

    # TODO: only do this if we're not the owner of the process.
    # maybe it makes sense to set. (Linux: /proc/pid/loginuid, macos:
    # sysctl with KERN_PROC, KERN_PROC_UID , ...

    ss = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    saved_umask = os.umask(0o000)
    ss.bind(comms.localpath)
    os.umask(saved_umask)
    ss.listen(0)

    try:
        # requires sudo on mac
        pymontrace.attacher.attach_and_exec(
            pid,
            format_bootstrap_snippet(
                probe, action, comms.remotepath,
                to_remote_path(pid, site_extension.name),
            )
        )

        # TODO: this needs a timeout
        s, addr = ss.accept()
        os.unlink(comms.localpath)

        print('Probes installed. Hit CTRL-C to end...', file=sys.stderr)
        try:
            header_fmt = struct.Struct('HH')
            while True:
                header = s.recv(4)
                if header == b'':
                    break
                (kind, size) = header_fmt.unpack(header)
                line = s.recv(size)
                out = (sys.stderr if kind == 2 else sys.stdout)
                out.write(line.decode())
            print('Target disconnected.')
        except KeyboardInterrupt:
            pass
        print('Removing probes...', file=sys.stderr)
        pymontrace.attacher.attach_and_exec(
            pid,
            format_untrace_snippet()
        )
    finally:
        try:
            ss.close()
        except Exception as e:
            print(f'closing {comms.localpath} failed:', repr(e), file=sys.stderr)
        try:
            os.unlink(comms.localpath)
        except FileNotFoundError:
            # We unlink already after connecting, when things went well
            pass
        except Exception as e:
            print(f'unlinking {comms.localpath} failed:', repr(e), file=sys.stderr)


def subprocess_entry(progpath, probe, action):
    import runpy
    import time

    from pymontrace.tracee import settrace

    comm_file = CommsFile(os.getpid()).remotepath
    while not os.path.exists(comm_file):
        time.sleep(1)
    settrace(probe[1:], action, comm_file)

    runpy.run_path(progpath, run_name='__main__')


# TODO: factor this with tracepid
def tracesubprocess(progpath: str, probe, action):

    probestr = ':'.join(map(str, probe))
    p = subprocess.Popen(
        [sys.executable, '-m', 'pymontrace', '-X', progpath, probestr, action]
    )

    comms = CommsFile(p.pid)

    ss = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    saved_umask = os.umask(0o000)
    ss.bind(comms.localpath)
    os.umask(saved_umask)
    ss.listen(0)

    try:
        s, addr = ss.accept()
        os.unlink(comms.localpath)

        print('Probes installed. Hit CTRL-C to end...', file=sys.stderr)
        try:
            header_fmt = struct.Struct('HH')
            while True:
                header = s.recv(4)
                if header == b'':
                    break
                (kind, size) = header_fmt.unpack(header)
                line = s.recv(size)
                out = (sys.stderr if kind == 2 else sys.stdout)
                out.write(line.decode())
            print('Target disconnected.')
        except KeyboardInterrupt:
            pass
        print('Removing probes...', file=sys.stderr)
        p.terminate()
    finally:
        try:
            ss.close()
        except Exception as e:
            print(f'closing {comms.localpath} failed:', repr(e), file=sys.stderr)
        try:
            os.unlink(comms.localpath)
        except FileNotFoundError:
            # We unlink already after connecting, when things went well
            pass
        except Exception as e:
            print(f'unlinking {comms.localpath} failed:', repr(e), file=sys.stderr)


def cli_main():
    args = parser.parse_args()

    if args.pyprog:
        tracesubprocess(args.pyprog, args.probe, args.action)
    elif args.subproc:
        subprocess_entry(args.subproc, args.probe, args.action)
    elif args.pid:
        tracepid(args.pid, args.probe, args.action)
    else:
        print('one or -p or -c required', file=sys.stderr)
        parser.print_usage(file=sys.stderr)
        exit(1)


if __name__ == '__main__':
    cli_main()
