#
# We skip attacher tests when not root on mac, but these ones should be
# fine to run.
#
import pytest


@pytest.mark.parametrize("args,exc_type", [
    (("wrong", [1, 2], "print('hi')"), TypeError, ),
    ((1, "wrong", "print('hi')"), TypeError, ),
    ((1, ["wrong"], "print('hi')"), TypeError,),
    ((1, [1, "wrong"], "print('hi')"), TypeError,),
    ((1, [1, 2, 3, 4, 5, 6, 7, 8, 9], "print('hi')"), ValueError,),
    ((1, [-5], "print('hi')"), OverflowError,),
])
def test_exec_in_threads(args, exc_type):
    from pymontrace import attacher

    with pytest.raises(exc_type):
        attacher.exec_in_threads(*args)
