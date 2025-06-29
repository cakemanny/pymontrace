# Probes

| Probe Name | Description
| ---------- | -----------
| [`pymontrace::BEGIN`](#_probe_begin), [`pymontrace::END`](#_probe_end) | `BEGIN` is executed after pymontrace successfully connects to a target. `END` is executed if tracing ends normally and before the program itself terminates. |
| [`line:`_filepath_`:`_line number_](#_probe_line) | Executes its action just before the matched line executes. |
| [`func:`_qpath_`:start`, `func:`_qpath_`:yield`, `func:`_qpath_`:resume`, `func:`_qpath_`:return`, `func:`_qpath_`:unwind`](#_probe_func) | Entry and exit points of python functions. |
| `call:`_qpath_`:before`, `call:`_qpath_`:after` | Before and after making a function call. The context is within the caller. _Not yet implemented_. |


## `pymontrace::BEGIN` { #_probe_begin }

`BEGIN` can be useful to set up initial values of variables.

Since it runs in the context of the traced target, it can also be used
to do simple state checks.

    pymontrace::BEGIN {{ import gc; print(gc.get_stats()); exit() }}

Another use for `BEGIN` is to import modules and define helper functions.
Since importing in python can be very expensive you'll want to avoid that
in a tight loop.
A way around that would be to import and assign to a variable on `vars`.

Example showing import in `BEGIN`:

    pymontrace::BEGIN {{
        import base64
        vars.b64decode = base64.b64decode
    }}

    line:*/target.py:123 {{
        print(vars.b64decode(some_base64_encoded_value))
    }}


## `pymontrace::END` { #_probe_end }

`END` fires at the end of tracing, including when you hit <kbd>CTRL+C</kbd>.

It can be used to print values that were saved in the `vars` namespace.


## `line:`_filepath_`:`_lineno_ { #_probe_line }

It corresponds to [sys.monitoring.events.LINE](https://docs.python.org/3/library/sys.monitoring.html#monitoring-event-LINE)
when tracing Python 3.12 and later.
It corresponds to the [`'line'` trace event](https://docs.python.org/3/library/sys.html#sys.settrace)
when tracing Python 3.11 and earlier.

For example, given a target:

<small>_target.py:_</small>
```python
import time         # 1
                    # 2
while True:         # 3
    time.sleep(1)   # 4
```

The following pymontrace program would fire on the just before the `time.sleep` call:
```
line:*/target.py:4 {{ ... }}
```


## `func:`_qpath_`:...` { #_probe_func }

`func` probes are able to monitor the entry and exit points of any python
function.

The _qpath_ segment is the module qualified function path.

To give an example, let's state the qpaths for if the following was imported
as `import helpers.helpful`

<small>_helpers/helpful.py:_</small>

```python
class Helper:
    def help(self):  # helpers.helpful.Helper.help
        pass

def make_helper():  # helpers.helpful.make_helper
    class Elf:
        def help(self):  # helpers.helpful.make_helper.<locals>.Elf.help
            pass
    return Elf().help()
```

<blockquote>

  Note: Using a module path based on a re-export will not match.

  For example, assuming the next two files are part of the traced process,
  the probe spec
  `func:requests.client.exceptions.ClientException.__init__:start`
  will match when `ClientException` is constructed,
  whereas
  `func:requests.exceptions.ClientException.__init__:start`
  will not.

  <small>_requests/exceptions.py:_</small>
  ```python
  from client.exceptions import ClientException
  __all__ = ("ClientException",)
  ```

  <small>_requests/clients/exceptions.py:_</small>
  ```python
  class ClientException(Exception):
      def __init__(*args):
          ...
  ```

</blockquote>

### Probe Sites

The following shows the positions of the probe sites in a representative
function

```python
def example():
    # start
    ...
    # yield
    yield
    # resume

    if ...:
        # unwind
        raise Exception

    # return
    return

async def coro():
    ...
    # yield
    await other()
    # resume
    ...
```


> Note: Tracking the `unwind` event causes some overhead when any exception is
raised within the target. Whereas, on Python 3.12 and later, tracking
for example `start` only causes overhead in matching functions.

> Note: `yield` and `resume` only match on Python 3.12 and later.
