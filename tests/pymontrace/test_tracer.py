
def test_parse_probe():
    from pymontrace.tracer import parse_probe

    assert parse_probe("line:path/to/filename.py:56") == (
        "line",
        "path/to/filename.py",
        56,
    )


def test_format_bootstrap_snippet():
    from pymontrace.tracer import format_bootstrap_snippet

    assert format_bootstrap_snippet((
        "line",
        "path/to/filename.py",
        56,
    ), 'print("a", a, "b", b)', '/tmp/pymontrace-654') == \
        "import pymontrace.tracee; pymontrace.tracee.settrace(('path/to/filename.py', 56), 'print(\"a\", a, \"b\", b)', '/tmp/pymontrace-654')"
