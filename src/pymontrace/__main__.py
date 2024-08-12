import struct
import socket
import os
import argparse
import sys

import pymontrace.attacher
from pymontrace.tracer import (
    parse_probe, format_bootstrap_snippet, format_untrace_snippet, CommsFile
)
# TODO
from pymontrace.tracee import settrace


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
    'probe',
    type=parse_probe,
    help='Example: line:script.py:13')
parser.add_argument(
    'action',
    help='a python expression to evaluate each time the probe site is reached')


def tracepid(pid: int, probe, action: str):
    # ... maybe use an ExitStack to refactor

    # Need to rethink directories when it comes to containers
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
            format_bootstrap_snippet(probe, action, comms.remotepath)
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


def cli_main():
    args = parser.parse_args()

    if args.pyprog:
        # FIXME: use runpy or subprocess or os.spawn
        #  (look at sys.executable maybe , maybe multiprocess.Process )
        with open(args.pyprog) as f:
            prog_code = compile(f.read(), args.pyprog, 'exec')

        settrace(args.probe[1:], args.action)

        prog_globals = {'__name__': '__main__'}
        exec(prog_code, prog_globals)
    elif args.pid:
        tracepid(args.pid, args.probe, args.action)
    else:
        print('one or -p or -c required', file=sys.stderr)
        parser.print_usage(file=sys.stderr)
        exit(1)


if __name__ == '__main__':
    cli_main()
