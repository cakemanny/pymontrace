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
