import subprocess
import pathlib


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
