
from pathlib import Path


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
