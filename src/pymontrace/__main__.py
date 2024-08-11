"""
Usage: pymontrace [options] -e pymontrace-expr
       pymontrace [options] -s script

Examples:

    # This will change !
    pymontrace line:examples/script_to_debug.py:13 'print("a", a, "b", b)' \\
        -c examples/script_to_debug.py

    python3 examples/script_to_debug.py
    pymontrace line:examples/script_to_debug.py:13 'print("a", a, "b", b)' \\
        -p $!

"""
import argparse
import signal
import sys

import pymontrace.attacher
from pymontrace.tracer import (
    parse_probe, format_bootstrap_snippet, format_untrace_snippet
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
    help='a python expression to each time the probe site is reached ')


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
        # requires sudo on mac
        pymontrace.attacher.attach_and_exec(
            args.pid,
            format_bootstrap_snippet(args.probe, args.action)
        )

        print('Probes installed. Hit CTRL-C to end...')
        try:
            signal.pause()
        except KeyboardInterrupt:
            print('Removing probes...')
            pymontrace.attacher.attach_and_exec(
                args.pid,
                format_untrace_snippet()
            )
    else:
        print('one or -p or -c required', file=sys.stderr)
        parser.print_usage(file=sys.stderr)
        exit(1)


if __name__ == '__main__':
    cli_main()
