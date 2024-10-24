import subprocess
import pathlib


def test_dash_c_mode():

    p = subprocess.run(
        [
            'pymontrace',
            '-c',
            'modulo_loop.py',
            '-e',
            'line:modulo_loop.py:4 {{ pmt.print("a", a) }}'
        ],
        cwd=(pathlib.Path('.') / 'integration_tests' / 'targets'),
        capture_output=True
    )
    p.check_returncode()
    assert b'a 1\na 2\na 3\n' in p.stdout
