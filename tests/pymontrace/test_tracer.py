import os
import ast


def test_parse_probe():
    from pymontrace.tracer import parse_probe

    assert parse_probe("line:path/to/filename.py:56") == (
        "line",
        "path/to/filename.py",
        56,
    )


def test_format_bootstrap_snippet():
    from pymontrace.tracer import format_bootstrap_snippet

    formatted = format_bootstrap_snippet(
        (
            "line",
            "path/to/filename.py",
            56,
        ),
        'print("a", a, "b", b)',
        "/tmp/pymontrace-654",
        "/tmp/tmp942aigv0",
    )

    assert formatted.endswith(
        "pymontrace.tracee.settrace(('path/to/filename.py', 56), 'print(\"a\", a, \"b\", b)', '/tmp/pymontrace-654')\n"
    )

    # This will error if we introduce a syntax error
    ast.parse(formatted)


def test_install_pymontrace():
    from pymontrace.tracer import install_pymontrace

    site_extension = install_pymontrace(os.getpid())

    assert os.stat(site_extension.name).st_mode & 0o755 == 0o755

    assert os.path.isfile(
        os.path.join(site_extension.name, "pymontrace", "__init__.py")
    )
    assert os.path.isfile(os.path.join(site_extension.name, "pymontrace", "tracee.py"))


def test_to_remote_path():
    from pymontrace.tracer import to_remote_path

    assert to_remote_path(1, '/tmp') == '/tmp'
    assert to_remote_path(1, '/proc/1/root/tmp') == '/tmp'
