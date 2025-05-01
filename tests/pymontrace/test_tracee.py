import typing
import sys
import struct
import inspect
import types

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


class FakeFrame(types.SimpleNamespace):
    def __init__(self, co_qualname: str, module_name: str):
        mod = types.ModuleType(module_name)
        self.f_globals = mod.__dict__
        self.f_locals = {}

        co_filename = f"{module_name.replace('.','/')}.py"

        names = co_qualname.split('.')
        co_name = names.pop()
        lines = [
            f'def {co_name}():',
            '  pass'
        ]
        while len(names):
            parent = names.pop()
            # indent
            lines = [f"  {line}" for line in lines]
            lines.insert(0, f"class {parent}:")
        module_code = compile('\n'.join(lines), co_filename, "exec")
        exec(module_code, mod.__dict__)
        obj = mod
        for name in co_qualname.split('.'):
            obj = getattr(obj, name)
        self.f_code = obj.__code__

    @classmethod
    def make(cls, co_qualname: str, module_name: str) -> types.FrameType:
        f = FakeFrame(co_qualname, module_name)
        return typing.cast(types.FrameType, f)

    @classmethod
    def code(cls, co_qualname: str) -> types.CodeType:
        c = FakeFrame(co_qualname, module_name='unimportant').f_code
        return typing.cast(types.CodeType, c)


@pytest.mark.parametrize('probe,frame,expect_match', [
    (FuncProbe('', 'foo', 'start'), FakeFrame.make('foo', 'a.b.c'), True),
    (FuncProbe('*', 'foo', 'start'), FakeFrame.make('foo', 'a.b.c'), True),
    (FuncProbe('*.c', 'foo', 'start'), FakeFrame.make('foo', 'a.b.c'), True),
])
def test_func_probe0(probe: FuncProbe, frame, expect_match: bool):
    assert probe.matches(frame) == expect_match


def test_func_probe__excludes():
    assert not FuncProbe('*', 'foo', 'start').excludes(FakeFrame.code('foo'))
    assert not FuncProbe('*.c', 'foo', 'start').excludes(FakeFrame.code('foo'))


@pytest.mark.skipif("sys.version_info < (3, 11)")
def test_func_probe__qualname():
    # Not gonna work on python 3.9 or 3.10 :(
    assert FuncProbe('*', 'c.foo', 'start').matches(FakeFrame.make('c.foo', 'a.b'))
    assert not FuncProbe('*', 'c.foo', 'start').excludes(FakeFrame.code('c.foo'))


def test_func_probe1():

    assert FuncProbe('*.b.c', 'foo', 'start').matches(FakeFrame.make('foo', 'a.b.c'))

    assert FuncProbe('', '*oo', 'start').matches(FakeFrame.make('foo', 'c'))
    assert FuncProbe('*ar', 'foo', 'start').matches(FakeFrame.make('foo', 'baz.bar'))
    assert FuncProbe('*bar*', '', 'start').matches(FakeFrame.make('foo', 'baz.bar'))
    assert FuncProbe('*bar*', '*', 'start').matches(FakeFrame.make('foo', 'baz.bar'))


def test_func_probe3():

    assert FuncProbe('os', 'get_exec_path', 'start').matches(
        FakeFrame.make('get_exec_path', 'os')
    )


def test_func_probe2():
    import sys
    import types

    fr: list[types.FrameType] = []

    def handle(frame: types.FrameType, event: str, arg):
        fr.append(frame)

    def foo():
        pass

    sys.settrace(handle)
    foo()
    sys.settrace(None)

    assert len(fr) == 1

    assert 'foo' in fr[0].f_back.f_locals
    assert FuncProbe('', '*.foo', 'start').matches(fr[0])


class SomeClass:
    def bar(self):
        pass


def test_func_probe2__qualname():
    import sys
    import types

    fr: list[types.FrameType] = []

    def handle(frame: types.FrameType, event: str, arg):
        fr.append(frame)

    foo = SomeClass()

    sys.settrace(handle)
    foo.bar()
    sys.settrace(None)

    assert len(fr) == 1

    assert FuncProbe('', 'SomeClass.bar', 'start').matches(fr[0])
    assert FuncProbe('', '*.bar', 'start').matches(fr[0])


def outer():
    def bar():
        pass
    return bar


def test_func_probe2__qualname2():
    import sys
    import types

    fr: list[types.FrameType] = []

    def handle(frame: types.FrameType, event: str, arg):
        fr.append(frame)

    baz = outer()

    sys.settrace(handle)
    baz()
    sys.settrace(None)

    assert len(fr) == 1

    assert FuncProbe('', '*.bar', 'start').matches(fr[0])
    assert FuncProbe('', 'outer.*.bar', 'start').matches(fr[0])


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

    probe = FuncProbe('', '*.make_frame', 'return')

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
