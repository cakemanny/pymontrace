import os
import ast
import textwrap

import pytest


def test_parse_script():
    from pymontrace.tracer import parse_script

    single_probe_script = 'line:*path/to/file.py:56 {{ pmt.print("yo") }}'

    probe_actions = parse_script(single_probe_script)

    assert probe_actions == [
        (('line', '*path/to/file.py', '56'), 'pmt.print("yo") ')
    ]


def test_parse_script__two_probes():
    from pymontrace.tracer import parse_script

    two_probe_script = """
    line:*path/to/file.py:56
    {{
        pmt.print("yo")
    }}

    line:*another.py:999
    {{
        pmt.print(a, b, c)
        pmt.print()
    }}
    """
    two_probe_script = textwrap.dedent(two_probe_script)

    assert parse_script(two_probe_script) == [
        (('line', '*path/to/file.py', '56'), '\npmt.print("yo")\n'),
        (('line', '*another.py', '999'), '\npmt.print(a, b, c)\npmt.print()\n'),
    ]


def test_validate_script():
    from pymontrace.tracer import validate_script

    script_text = 'line:path.py:1 {{ x() }}'
    # Doesn't throw
    validate_script(script_text)

    with pytest.raises(Exception):
        validate_script('invalid')


def test_encode_script():
    from pymontrace.tracer import encode_script

    encoded = encode_script('line:path.py:23 {{ print(x) }}')

    assert encoded == (
        b'\x01\x00'     # Version 1
        b'\x01\x00'     # Number of probes
        b'\x01'         # Line probe ID: 1
        b'\x02'         # Number of arguments
        b'path.py\x00'  # First argument
        b'23\x00'       # Second argument
        b'print(x) \x00'    # Action snippet
    )


def test_format_bootstrap_snippet():
    from pymontrace.tracer import format_bootstrap_snippet
    from pymontrace.tracer import _encode_script

    formatted = format_bootstrap_snippet(
        _encode_script(
            [
                (
                    ("line", "path/to/filename.py", "56",),
                    'print("a", a, "b", b) ',
                )
            ]
        ),
        "/tmp/pymontrace-654",
        "/tmp/tmp942aigv0",
    )

    assert (
        "pymontrace.tracee.connect('/tmp/pymontrace-654')\n"
    ) in formatted
    assert "pymontrace.tracee.settrace" in formatted

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


def test_get_proc_euid():
    from pymontrace.tracer import get_proc_euid

    assert get_proc_euid(os.getpid()) == os.geteuid()
    # This is probably not always true. e.g. in many linux containers
    assert get_proc_euid(1) == 0
