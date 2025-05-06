#
# We skip attacher tests when not root on mac, but these ones should be
# fine to run.
#
import signal
import pytest
import subprocess


@pytest.mark.parametrize("args,exc_type", [
    (("wrong", [1, 2], "print('hi')"), TypeError, ),
    ((1, "wrong", "print('hi')"), TypeError, ),
    ((1, ["wrong"], "print('hi')"), TypeError,),
    ((1, [1, "wrong"], "print('hi')"), TypeError,),
    ((1, [1, 2, 3, 4, 5, 6, 7, 8,
          9, 10, 11, 12, 13, 14, 15, 16, 17], "print('hi')"), ValueError,),
    ((1, [-5], "print('hi')"), OverflowError,),
])
def test_exec_in_threads(args, exc_type):
    from pymontrace import attacher

    with pytest.raises(exc_type):
        attacher.exec_in_threads(*args)


def test_reap_process():
    from pymontrace import attacher

    with subprocess.Popen(['/bin/sleep', '0.1']) as p:
        exitcode = attacher.reap_process(p.pid, 300)

    assert exitcode == 0


def test_reap_process__nonzero_exit():
    from pymontrace import attacher

    with subprocess.Popen(['/bin/sh', '-c', 'sleep 0.1; exit 3']) as p:
        exitcode = attacher.reap_process(p.pid, 300)

    assert exitcode == 3


def test_reap_process__signalled():
    from pymontrace import attacher

    with subprocess.Popen(['/bin/sh', '-c', 'sleep 0.1; kill -TERM $$']) as p:
        with pytest.raises(attacher.SignalledError) as exc_info:
            attacher.reap_process(p.pid, 300)

    assert exc_info.value.args[0] == 15
    assert exc_info.value.args[1] in ("Terminated: 15", "Terminated")


def test_reap_process__nolongerexisting():
    from pymontrace import attacher

    with subprocess.Popen(['/bin/sleep', '0']) as p:
        pass

    with pytest.raises(ProcessLookupError):
        # Hopefully we can be quite sure this process doesn't exist
        attacher.reap_process(p.pid, 300)


def test_reap_process__timeout():
    from pymontrace import attacher
    import sys

    # using str to thwart stupid pyrights disabling of the syntax highlighting
    if str(sys.platform) == 'darwin':

        with subprocess.Popen(['/bin/sleep', '0.3']) as p:
            with pytest.raises(TimeoutError):
                # Hopefully we can be quite sure this process doesn't exist
                attacher.reap_process(p.pid, 5)  # 1ms
    else:

        with subprocess.Popen(['/bin/sleep', '0.3']) as p:
            with pytest.raises(TimeoutError):
                # Hopefully we can be quite sure this process doesn't exist
                attacher.reap_process(p.pid, 5)  # 1ms
