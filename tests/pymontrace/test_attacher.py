import inspect
import os
import subprocess
import sys
import textwrap
import time

import pytest


if sys.platform == 'linux' or (sys.platform == 'darwin' and os.getuid() == 0):
    pass
else:
    pytest.skip(
        "skipping attach when non-linux and non-darwin root",
        allow_module_level=True,
    )


def func_body_to_script_text(func):
    lines, _ = inspect.getsourcelines(func)
    lines_wanted = lines[1:]
    return textwrap.dedent(''.join(lines_wanted))


def test_attach_and_exec():
    from pymontrace import attacher

    with subprocess.Popen(
        ['python3', '-u', '-c', 'import time\nwhile True: time.sleep(0.1)'],
        stdout=subprocess.PIPE,
    ) as p:
        try:
            time.sleep(0.01)

            attacher.attach_and_exec(p.pid, 'for _ in range(3): print("hello")')

            assert p.stdout
            stdout = os.read(p.stdout.fileno(), 10)
            assert b'hello' in stdout
        finally:
            # This seems to be necessary on macos, to avoid hanging
            p.terminate()


def test_attach_and_exec__bad_code():
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


multithreaded_program = """\
import os
import threading
import time
start = time.time()

def task():
    while time.time() < (start + 5.0):
        time.sleep(0.01)
    os._exit(1)  # avoid giving control back to the main thread.

t = threading.Thread(target=task)
t.start()
t.join()
"""


def test_attach_to_multithreaded_program():
    from pymontrace import attacher

    with subprocess.Popen(
        ['python3', '-u', '-c', multithreaded_program],
        stdout=subprocess.PIPE,
    ) as p:
        try:
            time.sleep(0.1)

            attacher.attach_and_exec(p.pid, 'for _ in range(3): print("hello")')

            assert p.stdout
            stdout = os.read(p.stdout.fileno(), 10)
            assert b'hello' in stdout
        finally:
            # This seems to be necessary on macos, to avoid hanging
            p.terminate()
