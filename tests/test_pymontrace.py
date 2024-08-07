
from pymontrace import LineProbe


def test_parse_probe():
    from pymontrace import parse_probe

    assert parse_probe("line:path/to/filename.py:56") == (
        "line",
        "path/to/filename.py",
        56,
    )


def test_format_bootstrap_snippet():
    from pymontrace import format_bootstrap_snippet

    assert format_bootstrap_snippet((
        "line",
        "path/to/filename.py",
        56,
    ), 'print("a", a, "b", b)') == \
        "import pymontrace; pymontrace.settrace(('path/to/filename.py', 56), 'print(\"a\", a, \"b\", b)')"


def test_line_probe():

    assert LineProbe('/a/b/c.py', 6).matches('/a/b/c.py', 6)
    assert not LineProbe('/a/b/c.py', 6).matches('/a/b/c.py', 7)

    assert LineProbe('*/c.py', 6).matches('/a/b/c.py', 6)

    assert LineProbe('/a/*/c.py', 6).matches('/a/b/c.py', 6)
    assert not LineProbe('/a/*/c.py', 6).matches('/a/b/c.pyx', 6)
