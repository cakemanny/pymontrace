
def test_tracebuffer(tmp_path):
    from pymontrace import tracebuffer

    fp = tmp_path / 'mapping'

    with tracebuffer.create(fp.as_posix()) as buffer:

        buffer.write(b"haady")
        assert buffer.read() == b"haady"
