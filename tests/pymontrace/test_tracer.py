import os
import ast
import textwrap

import pytest


def test_parse_script():
    from pymontrace.tracer import parse_script

    single_probe_script = 'line:*path/to/file.py:56 {{ print("yo") }}'

    probe_actions = parse_script(single_probe_script)

    assert probe_actions == [
        (('line', '*path/to/file.py', '56'), 'print("yo") ')
    ]


def test_parse_script__two_probes():
    from pymontrace.tracer import parse_script

    two_probe_script = """
    line:*path/to/file.py:56
    {{
        print("yo")
    }}

    line:*another.py:999
    {{
        print(ctx.a, ctx.b, ctx.c)
        print()
    }}
    """
    two_probe_script = textwrap.dedent(two_probe_script)

    assert parse_script(two_probe_script) == [
        (('line', '*path/to/file.py', '56'), '\nprint("yo")\n'),
        (('line', '*another.py', '999'), '\nprint(ctx.a, ctx.b, ctx.c)\nprint()\n'),
    ]


def test_parse_script__begin_and_end():
    from pymontrace.tracer import parse_script

    script = 'pymontrace::BEGIN {{ "junk" }}'

    probe_actions = parse_script(script)

    assert probe_actions == [
        (('pymontrace', '', 'BEGIN'), '"junk" ')
    ]

    with pytest.raises(Exception) as exc:
        parse_script('pymontrace::UNREAL {{"junk"}}')

    assert 'UNREAL' in str(exc.value)


def test_parse_script__func():
    from pymontrace.tracer import parse_script

    script = 'func:*.foo:start {{ print("hi") }}'

    probe_actions = parse_script(script)

    assert probe_actions == [
        (('func', '*.foo', 'start'), 'print("hi") ')
    ]

    with pytest.raises(Exception) as exc:
        parse_script('func:*.foo:unreal {{"junk"}}')

    assert 'unreal' in str(exc.value)

    with pytest.raises(Exception) as exc:
        parse_script('func:<badchars>:start {{"junk"}}')
    assert 'badchars' in str(exc.value)


def test_validate_script():
    from pymontrace.tracer import validate_script

    script_text = 'line:path.py:1 {{ x() }}'
    # Doesn't throw
    validate_script(script_text)

    with pytest.raises(Exception):
        validate_script('invalid')


def test_convert_probe_filter():
    from pymontrace.tracer import convert_probe_filter

    converted = convert_probe_filter('func:threading.*:end')

    assert converted == \
        "pymontrace::BEGIN {{ printprobes('func', 'threading.*', 'end') }} " \
        + "pymontrace::BEGIN {{ exit() }}"


def test_convert_probe_filter__invalid():
    from pymontrace.tracer import convert_probe_filter

    with pytest.raises(ValueError) as exc_info:
        convert_probe_filter('fun:xx:end')
    assert exc_info.match("Unknown probe name 'fun'")

    with pytest.raises(ValueError) as exc_info:
        convert_probe_filter('func:threading.*:end:')
    assert exc_info.match('Too many probe parts')

    with pytest.raises(ValueError) as exc_info:
        convert_probe_filter('func:threading.*:end {{ print(ctx.a) }}')
    assert "Unexpected '{' in probe filter" in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        convert_probe_filter('func:threading.*: end')
    assert "Unexpected space in probe filter" in str(exc_info.value)


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


def test_print_quantization():

    from pymontrace.tracee import Quantization
    from pymontrace.tracer import format_quantization

    q = Quantization()
    q.add(0)

    assert format_quantization(q) == """\
               value  ------------- Distribution ------------- count
                  -1 |                                         0
                   0 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ 1
                   1 |                                         0"""

    q.add(3)
    q.add(3)
    assert format_quantization(q) == """\
               value  ------------- Distribution ------------- count
                  -1 |                                         0
                   0 |@@@@@@@@@@@@@                            1
                   1 |                                         0
                   2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@              2
                   4 |                                         0"""
