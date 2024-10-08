import sys
import struct
import inspect

import pytest

from pymontrace.tracee import LineProbe, pmt, Message


def empty_user_action():
    return compile('pass', '<test>', 'exec')


def test_line_probe():

    assert LineProbe('/a/b/c.py', '6').matches('/a/b/c.py', 6)
    assert not LineProbe('/a/b/c.py', '6').matches('/a/b/c.py', 7)

    assert LineProbe('*/c.py', '6').matches('/a/b/c.py', 6)

    assert LineProbe('/a/*/c.py', '6').matches('/a/b/c.py', 6)
    assert not LineProbe('/a/*/c.py', '6').matches('/a/b/c.pyx', 6)


@pytest.mark.skipif("sys.version_info >= (3, 12)")
def test_handle_events():
    from pymontrace.tracee import create_event_handlers

    # The frame returned by currentframe changes its linenumber, so, we
    # use a dummy function to create a frame that doesn't move
    def make_frame():
        return inspect.currentframe()

    test_frame = make_frame()
    assert test_frame is not None

    lineno = inspect.getlineno(test_frame)
    probe = LineProbe(__file__, str(lineno))

    handler = create_event_handlers(probe, empty_user_action(), '')

    local_handler = handler(test_frame, 'call', None)
    assert local_handler is not None


@pytest.mark.skipif("sys.version_info >= (3, 12)")
def test_handle_events__wrong_function():
    from pymontrace.tracee import create_event_handlers

    # See other tests
    def make_frame():
        return inspect.currentframe()

    test_frame = make_frame()
    assert test_frame is not None

    this_frame = inspect.currentframe()
    assert this_frame is not None
    for probe in (LineProbe(__file__, '1'),
                  LineProbe(__file__, str(this_frame.f_lineno)),
                  LineProbe('/not/this/file.py', str(test_frame.f_lineno))):

        handler = create_event_handlers(probe, empty_user_action(), '')

        local_handler = handler(test_frame, 'call', None)
        assert local_handler is None


def test_pmt_print():

    encoded = pmt._encode_print('a', 1, 'b', 2)

    assert encoded == b'\x01\x00\x08\x00a 1 b 2\n'

    assert struct.unpack('=HH', encoded[:4]) == (Message.PRINT, 8,)
    assert len(encoded[4:]) == 8

    assert pmt._encode_print('a', 1, 'b', 2, sep='-', end='') \
        == b'\x01\x00\x07\x00a-1-b-2'


def test_pmt_print_error():

    encoded = pmt._encode_print('xxx', file=sys.stderr)

    assert encoded == b'\x02\x00\x04\x00xxx\n'
    assert encoded[0] == Message.ERROR


def test_pmt_encode_threads():

    encoded = pmt._encode_threads([7841, 7843])

    assert encoded == (
        b'\x03\x00'
        b'\x10\x00'
        b'\xa1\x1e\x00\x00\x00\x00\x00\x00'
        b'\xa3\x1e\x00\x00\x00\x00\x00\x00'
    )


def test_decode_pymontrace_program():
    from pymontrace.tracee import decode_pymontrace_program

    encoded = (
        b'\x01\x00'     # Version 1
        b'\x01\x00'     # Number of probes
        b'\x01'         # Line probe ID: 1
        b'\x02'         # Number of arguments
        b'path.py\x00'  # First argument
        b'23\x00'       # Second argument
        b'print(x) \x00'    # Action snippet
    )

    decoded = decode_pymontrace_program(encoded)

    assert decoded == [
        (LineProbe('path.py', '23'), 'print(x) '),
    ]
