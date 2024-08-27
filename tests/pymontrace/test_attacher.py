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


# Note: we use os.write instead of print, as print seems to write the \n
# separately
single_threaded_program = """\
import time
import os
os.write(1, b'started\\n')
start = time.time()
while time.time() < (start + 5.0):
    time.sleep(0.1)
"""


@pytest.fixture
def single_threaded_subprocess():
    with subprocess.Popen(
        [sys.executable, '-u', '-c', single_threaded_program],
        stdout=subprocess.PIPE,
    ) as p:
        try:
            assert p.stdout
            stdout = os.read(p.stdout.fileno(), len('started\n'))  # blocks until start
            assert stdout == b'started\n'

            yield p
        finally:
            # This seems to be necessary on macos, to avoid hanging
            p.terminate()


def test_attach_and_exec(single_threaded_subprocess):
    from pymontrace import attacher

    p = single_threaded_subprocess

    attacher.attach_and_exec(p.pid, 'for _ in range(3): print("hello")')

    stdout = os.read(p.stdout.fileno(), 10)
    assert b'hello' in stdout


def test_attach_and_exec__bad_code(single_threaded_subprocess):
    from pymontrace import attacher

    p = single_threaded_subprocess
    with pytest.raises(Exception):
        attacher.attach_and_exec(p.pid, 'pppprint("oh noh typoh")')


multithreaded_program = """\
import os
import threading
import time

start = time.time()

def task():
    os.write(1, b'started\\n')
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
        [sys.executable, '-u', '-c', multithreaded_program],
        stdout=subprocess.PIPE,
    ) as p:
        try:
            assert p.stdout
            stdout = os.read(p.stdout.fileno(), len('started\n'))  # blocks until start
            assert stdout == b'started\n'

            attacher.attach_and_exec(p.pid, 'for _ in range(3): print("hello")')

            assert p.stdout
            stdout = os.read(p.stdout.fileno(), 10)
            assert b'hello' in stdout
        finally:
            # This seems to be necessary on macos, to avoid hanging
            p.terminate()
