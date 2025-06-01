import sys
import struct
import inspect

import pytest

from pymontrace.tracee import FuncProbe, LineProbe, Message, remote


def empty_user_action():
    return compile('pass', '<test>', 'exec')


def test_line_probe():

    assert LineProbe('/a/b/c.py', '6').matches('/a/b/c.py', 6)
    assert not LineProbe('/a/b/c.py', '6').matches('/a/b/c.py', 7)

    assert LineProbe('*/c.py', '6').matches('/a/b/c.py', 6)

    assert LineProbe('/a/*/c.py', '6').matches('/a/b/c.py', 6)
    assert not LineProbe('/a/*/c.py', '6').matches('/a/b/c.pyx', 6)


@pytest.mark.skipif("sys.version_info >= (3, 12)")
def test_handle_events__line_probe():
    from pymontrace.tracee import create_event_handlers

    # The frame returned by currentframe changes its linenumber, so, we
    # use a dummy function to create a frame that doesn't move
    def make_frame():
        return inspect.currentframe()

    test_frame = make_frame()
    assert test_frame is not None

    lineno = inspect.getlineno(test_frame)
    probe = LineProbe(__file__, str(lineno))

    handler = create_event_handlers([(probe, empty_user_action(), '')])

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

        handler = create_event_handlers([(probe, empty_user_action(), '')])

        local_handler = handler(test_frame, 'call', None)
        assert local_handler is None


@pytest.mark.skipif("sys.version_info >= (3, 12)")
def test_handle_events__func_probe():
    from pymontrace.tracee import create_event_handlers

    # The frame returned by currentframe changes its linenumber, so, we
    # use a dummy function to create a frame that doesn't move
    def make_frame():
        return inspect.currentframe()

    test_frame = make_frame()
    assert test_frame is not None

    probe = FuncProbe('*.make_frame', 'return')

    handler = create_event_handlers([(probe, empty_user_action(), '')])

    local_handler = handler(test_frame, 'call', None)
    assert local_handler is not None


def test_pmt_print():

    encoded = remote._encode_print('a', 1, 'b', 2)

    assert encoded == b'\x01\x00\x08\x00a 1 b 2\n'

    assert struct.unpack('=HH', encoded[:4]) == (Message.PRINT, 8,)
    assert len(encoded[4:]) == 8

    assert remote._encode_print('a', 1, 'b', 2, sep='-', end='') \
        == b'\x01\x00\x07\x00a-1-b-2'


def test_pmt_print_error():

    encoded = remote._encode_print('xxx', file=sys.stderr)

    assert encoded == b'\x02\x00\x04\x00xxx\n'
    assert encoded[0] == Message.ERROR


def test_remote_encode_threads():

    encoded = remote._encode_threads([7841, 7843])

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


# Aggregations

@pytest.fixture(autouse=True, scope="module")
def reset_pmt():
    from pymontrace.tracee import pmt
    yield
    pmt._reset()


def test_vars():
    from pymontrace.tracee import pmt

    pmt.vars.xxx = 1
    assert pmt.vars.xxx == 1

    class Dumb:
        aggregate = 7

    pmt.vars.yyy = Dumb()
    assert pmt.vars.yyy.aggregate == 7


def test_agg_count():
    from pymontrace.tracee import agg, pmt

    pmt.maps.county['a'] = agg.count()
    assert pmt.maps.county['a'] == 1
    pmt.maps.county['a'] = agg.count()
    assert pmt.maps.county['a'] == 2

    pmt.maps[(1, 2)] = agg.count()
    pmt.maps[(1, 2)] = agg.count()
    pmt.maps[(1, 2)] = agg.count()
    assert pmt.maps[(1, 2)] == 3


def test_agg_sum():
    from pymontrace.tracee import agg, pmt

    pmt.maps.summy['a'] = agg.sum(1)
    pmt.maps.summy['a'] = agg.sum(2)
    pmt.maps.summy['a'] = agg.sum(3)

    assert pmt.maps.summy['a'] == 6


def test_agg_min():
    from pymontrace.tracee import agg, pmt

    pmt.maps.minny['a'] = agg.min(1)
    pmt.maps.minny['a'] = agg.min(2)
    pmt.maps.minny['a'] = agg.min(3)

    assert pmt.maps.minny['a'] == 1

    pmt.maps.minny['b'] = agg.min(3)
    pmt.maps.minny['b'] = agg.min(2)
    pmt.maps.minny['b'] = agg.min(1)

    assert pmt.maps.minny['b'] == 1


def test_agg_max():
    from pymontrace.tracee import agg, pmt

    pmt.maps.maxxy['a'] = agg.max(1)
    pmt.maps.maxxy['a'] = agg.max(2)
    pmt.maps.maxxy['a'] = agg.max(3)

    assert pmt.maps.maxxy['a'] == 3

    pmt.maps.maxxy['b'] = agg.max(3)
    pmt.maps.maxxy['b'] = agg.max(2)
    pmt.maps.maxxy['b'] = agg.max(1)

    assert pmt.maps.maxxy['b'] == 3


class TestQuantization:

    @staticmethod
    def test_quantize():
        from pymontrace.tracee import Quantization

        assert Quantization.quantize(0) == 0
        assert Quantization.quantize(1) == 1
        assert Quantization.quantize(2) == 2
        assert Quantization.quantize(3) == 2

        assert [Quantization.quantize(x) for x in range(10)] == [
            0, 1, 2, 2, 4, 4, 4, 4, 8, 8
        ]

        #                    v       v   v   v       v
        negative = [-1, -2, -3, -4, -5, -6, -7, -8, -9]
        expected = [-1, -2, -2, -4, -4, -4, -4, -8, -8]
        assert [Quantization.quantize(x) for x in negative] == expected

    @staticmethod
    def test_bucket_idx():
        from pymontrace.tracee import Quantization

        assert Quantization.bucket_idx(0) == 0
        assert Quantization.bucket_idx(1) == 1
        assert Quantization.bucket_idx(2) == 2
        assert Quantization.bucket_idx(3) == 2
        assert Quantization.bucket_idx(4) == 3

        assert [Quantization.bucket_idx(x) for x in range(10)] == [
            0, 1, 2, 2, 3, 3, 3, 3, 4, 4
        ]

        #            -   -----   -------------   -----
        negative = [-1, -2, -3, -4, -5, -6, -7, -8, -9]
        expected = [ 0,  1,  1,  2,  2,  2,  2,  3,  3]  # noqa
        assert [Quantization.bucket_idx(x) for x in negative] == expected


def test_agg_quantize():
    from pymontrace.tracee import agg, pmt

    pmt.maps.quanty['a'] = agg.quantize(0)
    assert pmt.maps.quanty['a'].buckets == [1]
    pmt.maps.quanty['a'] = agg.quantize(0)
    assert pmt.maps.quanty['a'].buckets == [2]
    pmt.maps.quanty['a'] = agg.quantize(1)
    assert pmt.maps.quanty['a'].buckets == [2, 1]
    pmt.maps.quanty['a'] = agg.quantize(2)
    pmt.maps.quanty['a'] = agg.quantize(3)
    assert pmt.maps.quanty['a'].buckets == [2, 1, 2]
