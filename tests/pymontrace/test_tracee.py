from pymontrace.tracee import LineProbe


def test_line_probe():

    assert LineProbe('/a/b/c.py', 6).matches('/a/b/c.py', 6)
    assert not LineProbe('/a/b/c.py', 6).matches('/a/b/c.py', 7)

    assert LineProbe('*/c.py', 6).matches('/a/b/c.py', 6)

    assert LineProbe('/a/*/c.py', 6).matches('/a/b/c.py', 6)
    assert not LineProbe('/a/*/c.py', 6).matches('/a/b/c.pyx', 6)
