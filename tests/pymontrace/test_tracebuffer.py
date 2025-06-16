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


def test_encode_value():
    from pymontrace.tracee import PMTMap, Quantization
    from pymontrace import tracebuffer

    expected = (b'\t\x00\x00\x00Q\x01\x00\x00\x00\x00\x00\x00\x00')

    assert PMTMap._encode_value(1) == expected
    assert tracebuffer.encode_value(1, Quantization) == expected


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
