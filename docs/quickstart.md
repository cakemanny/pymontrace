# Quick Start

## Installation

pymontrace may be installed from [PyPI](https://pypi.org/project/pymontrace/)
either using `pip` or `pipx` as the situation calls.

```shell
pip install pymontrace
```

```shell
pipx install pymontrace
```

It's also possible to run without an explicit install using `pipx run` or
`uvx`.


## Simple Examples

The following are pretty naïve but illustrative.
We make the assumption you are able to find the process ID (PID) of a process
you wish to trace and we use the dummy value 1234 here.

### Listing probes

List every top level python function and class method of every loaded module.
The points at which the `func` probe may attach.

```shell
pymontrace -p 1234 -l 'func:*:start'
```

> Note: on macOS you'll need to use `sudo` to trace a running process.

List all probe sites of a module:

```shell
pymontrace -p 1234 -l 'func:mymodule.*:'
```

List every line of every loaded module:

```shell
pymontrace -p 1234 -l 'line:'
```

> Note: You'll likely see the warning `WARN: dropped buffer(s)` whizz past
> and not see many files with names starting near the start of the alphabet.
> pymontrace drops trace data if too much is produced too quickly. It's best
> to try to employ some filters.

List the first line of every loaded module

```shell
pymontrace -p 1234 -l 'line::1'
```

List every line of the `contextlib` module:

```shell
pymontrace -p 1234 -l 'line:*/contextlib.py:'
```

### Tracing

Observe the entrance to every python function call. Use CTRL-C to end.

```shell
pymontrace -p 1234 -e 'func:*:start {{ print(qualname()) }}'
```

Observe the entry and exit to every python function from a module,
including the arguments it was called with.

```shell
pymontrace -p 1234 -e '
func:mymodule.*:start {{ print("->", funcname(), args()) }}
func:mymodule.*:return {{ print("<-", funcname()) }}
'
```

Count the number of times each function is called during the duration of the
trace.

```shell
pymontrace -p 1234 -e 'func:*:start {{ maps.calls[qualname()] = agg.count() }}'
```

Print the minimum and maximum value that a given function was called with

```shell
pymontrace -p 1234 -e '
func:mymodule.myfunc:start {{
    arg0 = next(iter(args().values()))
    vars.maxval = agg.max(arg0)
    vars.minval = agg.min(arg0)
}}
pymontrace::END {{
    print("max =", vars.maxval)
    print("min =", vars.minval)
}}
'
```

Plot a histogram of the ms durations of a top-level function called `g`:

```shell
pymontrace -p 1234 -e '
pymontrace::BEGIN {{
    import time
    import threading
    vars.monotime = time.monotonic_ns
    vars.threads = {}
    vars.get_ident = threading.get_ident
}}

func:__main__.g:start {{
  vars.threads[vars.get_ident()] = vars.monotime()
}}

func:__main__.g:return {{
    end = vars.monotime()
    i = vars.get_ident()
    if (start := vars.threads.pop(i, 0)) != 0:
        maps.calls[i] = agg.quantize((end - start) / 1000 / 1000)
}}
'
```

Which may output something like the following:

```
Waiting for process to reach safepoint...
Probes installed. Hit CTRL-C to end...
^CRemoving probes...
Waiting for process to reach safepoint...
calls

  8562249600:
               value  ------------- Distribution ------------- count
                 128 |                                         0
                 256 |@@@@@@@@@@@@@@@@@@@@@@@                  4
                 512 |@@@@@@@@@@@                              2
                1024 |                                         0
                2048 |                                         0
                4096 |                                         0
                8192 |                                         0
               16384 |                                         0
               32768 |                                         0
               65536 |                                         0
              131072 |                                         0
              262144 |                                         0
              524288 |                                         0
             1048576 |                                         0
             2097152 |                                         0
             4194304 |                                         0
             8388608 |                                         0
            16777216 |                                         0
            33554432 |                                         0
            67108864 |                                         0
           134217728 |                                         0
           268435456 |                                         0
           536870912 |                                         0
          1073741824 |                                         0
          2147483648 |@@@@@@                                   1
          4294967296 |                                         0
```

### Tracing Scripts

Visualize the execution flow of a script

```shell
pymontrace -c 'myscript.py 1 7' -e '

pymontrace::BEGIN {{
    vars.prefix = ""
}}

func:__main__.*:start {{
    print(vars.prefix, "->", funcname())
    vars.prefix += "  "
}}

func:__main__.*:return {{
    vars.prefix = vars.prefix[:-2]
    print(vars.prefix, "<-", funcname())
}}
func:__main__.*:unwind {{
    vars.prefix = vars.prefix[:-2]
    print(vars.prefix, "<*", funcname())
}}
'
```

Which could output something similar to:

```
Probes installed. Hit CTRL-C to end...
 -> <module>
   -> main
     -> f
       -> g
       <- g
       -> g
       <- g
       -> g
       <- g
       -> g
       <- g
       -> g
^C       <* g
     <* f
   <* main
 <* <module>
```
