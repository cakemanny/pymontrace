import time
import sys
import os
import subprocess

import pytest


if sys.platform == 'linux' or (sys.platform == 'darwin' and os.getuid() == 0):
    pass
else:
    pytest.skip(
        "skipping attach when non-linux and non-darwin root",
        allow_module_level=True,
    )


def test_attach_and_exec():
    from pymontrace import attacher

    with subprocess.Popen(
        ['python3', '-u', '-c', 'import time\nwhile True: time.sleep(0.1)'],
        stdout=subprocess.PIPE,
    ) as p:
        try:
            time.sleep(0.01)

            attacher.attach_and_exec(p.pid, 'for _ in range(3): print("hello")')

            stdout = os.read(p.stdout.fileno(), 10)
            assert b'hello' in stdout
        finally:
            # This seems to be necessary on macos, to avoid hanging
            p.terminate()


def test_attach_and_exec__bad_code():
    if sys.platform == 'darwin':
        pytest.skip(reason='work in progress')
    from pymontrace import attacher

    with subprocess.Popen(
        ['python3', '-u', '-c', 'import time\nwhile True: time.sleep(0.1)'],
        stdout=subprocess.PIPE,
    ) as p:
        try:
            time.sleep(0.01)

            with pytest.raises(Exception):
                attacher.attach_and_exec(p.pid, 'pppprint("oh noh typoh")')

        finally:
            # This seems to be necessary on macos, to avoid hanging
            p.terminate()
