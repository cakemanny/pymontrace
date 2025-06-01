import os
import pathlib
import signal
import subprocess
import sys
import textwrap
from typing import Union

import pytest


def test_dash_c_mode():

    p = subprocess.run(
        [
            'pymontrace',
            '-c',
            'modulo_loop.py',
            '-e',
            'line:modulo_loop.py:4 {{ print("a", ctx.a) }}'
        ],
        cwd=(pathlib.Path('.') / 'integration_tests' / 'targets'),
        capture_output=True
    )
    p.check_returncode()
    assert b'a 1\na 2\na 3\n' in p.stdout
    assert b'Traceback' not in p.stderr


def test_func_probe():

    p = subprocess.run(
        [
            'pymontrace',
            '-c',
            'modulo_loop.py',
            '-e',
            'func:*.inner:start {{ print("a", ctx.a) }}'
        ],
        cwd=(pathlib.Path('.') / 'integration_tests' / 'targets'),
        capture_output=True
    )
    p.check_returncode()
    assert b'a 1\na 2\na 3\n' in p.stdout
    assert b'Traceback' not in p.stderr


def wait_for_started(p: subprocess.Popen):
    # Most of the programs in this test suite write b'started\n' to stdout
    # as a syncronisation point.
    assert p.stdout
    stdout = os.read(p.stdout.fileno(), len('started\n'))  # blocks until start
    assert stdout == b'started\n'


def get_ptrace_scope() -> Union[int, None]:
    scope_file = "/proc/sys/kernel/yama/ptrace_scope"
    if os.path.isfile(scope_file):
        with open(scope_file) as f:
            return int(f.read().strip())
    return None


def test_end_probe():
    if sys.platform == 'darwin' and os.getuid() != 0:
        pytest.skip('needs root on darwin')
    if str(sys.platform) == 'linux' and (scope := get_ptrace_scope()) not in (None, 0):
        msg = f'need ptrace_scope: 0, found: {scope}'
        if os.getenv("CI"):
            pytest.fail(msg)
        else:
            pytest.skip(msg)

    target_program = textwrap.dedent(
        """
        import os, time
        os.write(1, b'started\\n')
        start = time.time()
        while time.time() < (start + 3.0):
            time.sleep(0.1)
        """
    )

    with subprocess.Popen(
        [
            sys.executable,
            '-u',
            '-c',
            target_program,
        ],
        stdout=subprocess.PIPE,
    ) as target_p:
        wait_for_started(target_p)

        env = dict(os.environ)
        env.update({'PYTHONUNBUFFERED': '1'})

        p = subprocess.Popen(
            [
                'pymontrace',
                '-p',
                str(target_p.pid),
                '-e',
                ('pymontrace::BEGIN {{ print("HIYA") }} '
                 'pymontrace::END {{ print("BYEE") }}')
            ],
            env=env,
            stdout=subprocess.PIPE,
        )
        assert p.stdout is not None
        os.read(p.stdout.fileno(), len("HIYA\n"))
        os.kill(p.pid, signal.SIGINT)

        output = os.read(p.stdout.fileno(), len("BYEE\n"))
        assert b'BYEE' in output

        target_p.terminate()
