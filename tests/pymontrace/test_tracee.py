import inspect

from pymontrace.tracee import LineProbe


def empty_user_action():
    return compile('pass', '<test>', 'exec')


def test_line_probe():

    assert LineProbe('/a/b/c.py', 6).matches('/a/b/c.py', 6)
    assert not LineProbe('/a/b/c.py', 6).matches('/a/b/c.py', 7)

    assert LineProbe('*/c.py', 6).matches('/a/b/c.py', 6)

    assert LineProbe('/a/*/c.py', 6).matches('/a/b/c.py', 6)
    assert not LineProbe('/a/*/c.py', 6).matches('/a/b/c.pyx', 6)


def test_handle_events():
    from pymontrace.tracee import create_event_handlers

    # The frame returned by currentframe changes its linenumber, so, we
    # use a dummy function to create a frame that doesn't move
    def make_frame():
        return inspect.currentframe()

    test_frame = make_frame()
    assert test_frame is not None

    lineno = inspect.getlineno(test_frame)
    probe = LineProbe(__file__, lineno)

    handler = create_event_handlers(probe, empty_user_action(), '')

    local_handler = handler(test_frame, 'call', None)
    assert local_handler is not None


def test_handle_events__wrong_function():
    from pymontrace.tracee import create_event_handlers

    # See other tests
    def make_frame():
        return inspect.currentframe()

    test_frame = make_frame()
    assert test_frame is not None

    this_frame = inspect.currentframe()
    assert this_frame is not None
    for probe in (LineProbe(__file__, 1),
                  LineProbe(__file__, this_frame.f_lineno),
                  LineProbe('/not/this/file.py', test_frame.f_lineno)):

        handler = create_event_handlers(probe, empty_user_action(), '')

        local_handler = handler(test_frame, 'call', None)
        assert local_handler is None
