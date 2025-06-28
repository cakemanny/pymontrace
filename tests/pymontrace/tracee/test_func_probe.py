import sys
import types
import inspect


class FakeFrame:
    def __init__(self, co_qualname: str, module_name: str):
        mod = types.ModuleType(module_name)
        self.f_globals = mod.__dict__
        self.f_locals = {}

        co_filename = f"{module_name.replace('.', '/')}.py"

        names = co_qualname.split('.')
        co_name = names.pop()
        lines = [
            f'def {co_name}():',
            '  return inspect.currentframe()'
        ]
        while len(names):
            parent = names.pop()
            # indent
            lines = [f"  {line}" for line in lines]
            lines.insert(0, f"class {parent}:")
        lines.insert(0, 'import inspect')
        module_code = compile('\n'.join(lines), co_filename, "exec")
        exec(module_code, mod.__dict__)
        obj = mod
        for name in co_qualname.split('.'):
            obj = getattr(obj, name)
        assert inspect.isfunction(obj)
        self.func = obj
        self.f_code: types.CodeType = obj.__code__

    @classmethod
    def make(cls, co_qualname: str, module_name: str) -> types.FrameType:
        f = FakeFrame(co_qualname, module_name).func
        return f()

    @classmethod
    def code(cls, co_qualname: str) -> types.CodeType:
        return FakeFrame(co_qualname, module_name='unimportant').f_code


def test_func_probe_matches():
    from pymontrace.tracee import FuncProbe

    assert FuncProbe('*.foo', 'start').matches(FakeFrame.make('foo', 'a.b.c'))
    assert not FuncProbe('*.foo', 'start').excludes(FakeFrame.code('foo'))
    assert FuncProbe('*.c.foo', 'start').matches(FakeFrame.make('foo', 'a.b.c'))
    assert not FuncProbe('*.c.foo', 'start').excludes(FakeFrame.code('foo'))
    assert FuncProbe('*.c.foo', 'start').matches(FakeFrame.make('c.foo', 'a.b'))
    assert not FuncProbe('*.c.foo', 'start').excludes(FakeFrame.code('c.foo'))
    assert FuncProbe('*.b.c.foo', 'start').matches(FakeFrame.make('foo', 'a.b.c'))

    assert FuncProbe('*oo', 'start').matches(FakeFrame.make('foo', 'c'))
    assert FuncProbe('*ar.foo', 'start').matches(FakeFrame.make('foo', 'baz.bar'))
    assert FuncProbe('*bar*', 'start').matches(FakeFrame.make('foo', 'baz.bar'))


def test_func_probe3():
    from pymontrace.tracee import FuncProbe

    assert FuncProbe('os.get_exec_path', 'start').matches(
        FakeFrame.make('get_exec_path', 'os')
    )


def test_func_probe2():
    from pymontrace.tracee import FuncProbe

    fr: list[types.FrameType] = []

    def handle(frame: types.FrameType, event: str, arg):
        fr.append(frame)

    def foo():
        pass

    sys.settrace(handle)
    foo()
    sys.settrace(None)

    assert len(fr) == 1

    assert FuncProbe('*.foo', 'start').matches(fr[0])


class SomeClass:
    def bar(self):
        pass


def test_func_probe2__qualname():
    from pymontrace.tracee import FuncProbe

    fr: list[types.FrameType] = []

    def handle(frame: types.FrameType, event: str, arg):
        fr.append(frame)

    foo = SomeClass()

    sys.settrace(handle)
    foo.bar()
    sys.settrace(None)

    assert len(fr) == 1

    assert FuncProbe('*.SomeClass.bar', 'start').matches(fr[0])
    assert FuncProbe('*.bar', 'start').matches(fr[0])


def outer():
    def bar():
        pass
    return bar


def test_func_probe2__qualname2():
    from pymontrace.tracee import FuncProbe

    fr: list[types.FrameType] = []

    def handle(frame: types.FrameType, event: str, arg):
        fr.append(frame)

    baz = outer()

    sys.settrace(handle)
    baz()
    sys.settrace(None)

    assert len(fr) == 1

    assert FuncProbe('*.bar', 'start').matches(fr[0])
    assert FuncProbe('*.outer.*.bar', 'start').matches(fr[0])


def test_list_sites():
    from pymontrace.tracee import FuncProbe

    listing = list(FuncProbe.listsites("pymontrace.tracee.*", "start"))

    assert len([x for x in listing if 'FuncProbe.listsites' in x]) == 1
    entry = [x for x in listing if 'FuncProbe.listsites' in x][0]
    assert entry.startswith('func:pymontrace.tracee.FuncProbe.listsites:start'), entry
