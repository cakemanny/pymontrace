import inspect
import os
import signal
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


def test_receiving_signal_during_attach():

    slow_program = textwrap.dedent("""\
    import time
    import os
    os.write(1, b'started\\n')
    start = time.time()
    time.sleep(1)
    time.sleep(1)
    """)

    p0 = subprocess.Popen([sys.executable, '-u', '-c', slow_program],
                          stdout=subprocess.PIPE)
    assert p0.stdout
    stdout = os.read(p0.stdout.fileno(), len('started\n'))
    assert stdout == b'started\n'

    attach_program = textwrap.dedent(f"""\
    from pymontrace import attacher

    attacher.attach_and_exec({p0.pid}, 'print("hello")')
    """)
    attach_proc = subprocess.Popen([sys.executable, '-u', '-c', attach_program])

    time.sleep(0.3)

    os.kill(attach_proc.pid, signal.SIGTERM)

    attach_return_code = attach_proc.wait()
    assert attach_return_code != 0

    # i.e. p0 should survive until it ends naturally
    assert p0.wait() == 0

    p0.terminate()


def test_exec_in_threads():
    if sys.platform != 'linux' and not (sys.platform == 'darwin'
                                        and os.uname().machine == 'arm64'):
        pytest.skip('per thread exec only implemented on linux so far')
    # TODO: exclude riscv

    from pymontrace import attacher

    program_text = textwrap.dedent("""\
    import os
    import threading
    import time

    start = time.time()

    def task():
        os.write(1, (str(threading.get_native_id()) + '\\n').encode())
        while time.time() < (start + 5.0):
            time.sleep(0.01)

    t = threading.Thread(target=task)
    t.start()
    task()
    t.join()
    """)

    p = subprocess.Popen(
        [sys.executable, '-u', '-c', program_text], stdout=subprocess.PIPE,
    )
    try:
        tid0 = int(p.stdout.readline().decode().strip())
        tid1 = int(p.stdout.readline().decode().strip())
        assert tid0 != 0
        assert tid1 != 0

        attacher.exec_in_threads(
            p.pid,
            (tid0, tid1),
            'import threading;\n'
            'tid = threading.get_native_id()\n'
            'print(f"hello{tid}\\n", end="", flush=True)\n'
        )
        p.terminate()
        line0 = p.stdout.readline().decode().strip()
        line1 = p.stdout.readline().decode().strip()

        assert [line0, line1] in (
            [f"hello{tid0}", f"hello{tid1}"],
            [f"hello{tid1}", f"hello{tid0}"],
        )
    finally:
        p.terminate()
