
def test_mapbuffer(tmp_path):
    from pymontrace import mapbuffer

    fp = tmp_path / 'mapping'

    with mapbuffer.create(fp.as_posix()) as buffer:

        buffer.write(b"haady")
        assert buffer.read() == b"haady"
