from pathlib import Path

import pytest


def test_tracebuffer(tmp_path: Path):
    from pymontrace import tracebuffer

    fp = tmp_path / 'mapping'

    with tracebuffer.create(fp.as_posix()) as buffer:

        buffer.write(b"haady")
        assert buffer.read() == b"haady"
        assert buffer.read() == b""
        buffer.write(b"kaity")
        buffer.write(b"spacey")
        assert buffer.read() == b"kaityspacey"


def test_agg_buffer(tmp_path: Path):
    from pymontrace import tracebuffer

    path = tmp_path / 'agg'

    buffer = tracebuffer.create_agg_buffer('bill', path.as_posix())

    assert buffer.name == 'bill'
    with buffer:
        assert buffer.epoch == 2

    offset, size = buffer.write(b"hello")
    buffer.update(b"hallo", offset, size)

    assert buffer.read(offset, size) == b"hallo"
    buffer.write(b"moar")
    assert buffer.read(offset, size) == b"hallo"
    assert buffer._agg_buffer.readall(buffer.epoch) == b"hallomoar"

    assert buffer.written(2) == 9

    assert buffer.agg_op == 0
    buffer.agg_op = 2
    assert buffer.agg_op == 2

    with pytest.raises(ValueError):
        buffer.agg_op = -1
    with pytest.raises(ValueError):
        buffer.agg_op = 6


def test_encode_entry():
    from pymontrace.tracee import PMTMap, Quantization
    from pymontrace import tracebuffer

    expected = (b'\x14\x00\x00\x00'
                b'\x80\x04\x95\t\x00\x00\x00\x00\x00\x00\x00\x8c\x05hello\x94.'
                b'\t\x00\x00\x00Q\x01\x00\x00\x00\x00\x00\x00\x00')

    assert PMTMap._encode('hello', 1) == expected
    assert tracebuffer.encode_entry('hello', 1, Quantization) == expected

    expected = PMTMap._encode('some key', 3.4)
    assert tracebuffer.encode_entry('some key', 3.4, Quantization) == expected


def test_encode_value():
    from pymontrace.tracee import PMTMap, Quantization
    from pymontrace import tracebuffer

    expected = b'\t\x00\x00\x00Q\x01\x00\x00\x00\x00\x00\x00\x00'

    assert PMTMap._encode_value(1) == expected
    assert tracebuffer.encode_value(1, Quantization) == expected

    expected = PMTMap._encode_value(-7)
    assert tracebuffer.encode_value(-7, Quantization) == expected

    expected = PMTMap._encode_value(3.4)
    assert tracebuffer.encode_value(3.4, Quantization) == expected

    q = Quantization()
    q.add(1)
    q.add(7)
    q.add(12398)
    expected = PMTMap._encode_value(q)
    assert tracebuffer.encode_value(q, Quantization) == expected


def test_encode_value__refleaks():
    import sys

    from pymontrace.tracee import Quantization
    from pymontrace import tracebuffer

    if not hasattr(sys, 'gettotalrefcount'):
        pytest.skip("needs debug python build")

    q = Quantization()
    q.add(1)
    q.add(7)
    q.add(12398)

    for _ in range(10):
        # warm up
        tracebuffer.encode_value(q, Quantization)

    before = sys.gettotalrefcount()
    for _ in range(n := 1000):
        tracebuffer.encode_value(q, Quantization)
    after = sys.gettotalrefcount()
    print((after - before) / n)
    assert after - before < 200


def test_decode_value():
    from pymontrace.tracee import PMTMap, Quantization
    from pymontrace import tracebuffer

    data = (b'\x14\x00\x00\x00'
            b'\x80\x04\x95\t\x00\x00\x00\x00\x00\x00\x00\x8c\x05hello\x94.'
            b'\t\x00\x00\x00Q\x01\x00\x00\x00\x00\x00\x00\x00')

    assert PMTMap._decode_value(data) == 1
    assert tracebuffer.decode_value(data, Quantization) == 1

    data = PMTMap._encode('some key', -7)
    assert tracebuffer.decode_value(data, Quantization) == -7

    q = Quantization()
    q.add(1)
    q.add(7)
    q.add(12398)
    data = PMTMap._encode('some key', q)
    # action
    decoded = tracebuffer.decode_value(data, Quantization)
    assert isinstance(decoded, Quantization)
    assert decoded.buckets == q.buckets


def test_decode_value__refleaks():
    import sys

    from pymontrace.tracee import Quantization
    from pymontrace import tracebuffer

    if not hasattr(sys, 'gettotalrefcount'):
        pytest.skip("needs debug python build")

    q = Quantization()
    q.add(1)
    q.add(7)
    q.add(12398)
    data = tracebuffer.encode_entry('some key', q, Quantization)

    # warm up
    for _ in range(10):
        tracebuffer.decode_value(data, Quantization)

    before = sys.gettotalrefcount()
    for _ in range(n := 1000):
        tracebuffer.decode_value(data, Quantization)
    after = sys.gettotalrefcount()
    print((after - before) / n)
    assert after - before < 200


def test_decode_value__double():
    from pymontrace.tracee import Quantization
    from pymontrace import tracebuffer

    data = tracebuffer.encode_entry('some key', 3.4, Quantization)
    assert tracebuffer.decode_value(data, Quantization) == 3.4


@pytest.mark.skip(reason="enable to test perf")
def test_encode_perf():
    import time

    from pymontrace.tracee import PMTMap, Quantization
    from pymontrace import tracebuffer

    start = time.monotonic_ns()
    for _ in range(1_000_000):
        tracebuffer.encode_entry('a', 10, Quantization)
    end = time.monotonic_ns()
    avg_op_micros = (end - start) / 1_000_000_000
    # 0.29047µs
    print(f"avg max: {avg_op_micros:.5}µs")

    start = time.monotonic_ns()
    for _ in range(1_000_000):
        PMTMap._encode('a', 10)
    end = time.monotonic_ns()
    avg_op_micros = (end - start) / 1_000_000_000

    # 0.40991µs as committed before
    print(f"avg max: {avg_op_micros:.5}µs")

    # encode_value

    start = time.monotonic_ns()
    for _ in range(1_000_000):
        tracebuffer.encode_value(10, Quantization)
    end = time.monotonic_ns()
    avg_op_micros = (end - start) / 1_000_000_000
    # 0.29047µs
    print(f"avg max: {avg_op_micros:.5}µs")

    start = time.monotonic_ns()
    for _ in range(1_000_000):
        PMTMap._encode_value(10)
    end = time.monotonic_ns()
    avg_op_micros = (end - start) / 1_000_000_000

    # 0.40991µs as committed before
    print(f"avg max: {avg_op_micros:.5}µs")
    assert False
