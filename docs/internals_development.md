# pymontrace internals

## debugging the attacher

If the attacher seems to hang attaching to a particular program, check that
the target is calling our attachment "safe point". `PyEval_SaveThread` as at
writing.

On macOS, with only the target running

```sh
sudo dtrace -n pid$(pgrep Python):Python:Py\*:entry'{ trace(probefunc); }'
```

```
...
  3 461242           PyFloat_AsDouble:entry PyFloat_AsDouble
  3 461698          PyEval_SaveThread:entry PyEval_SaveThread   <--
  3 461699       PyEval_RestoreThread:entry PyEval_RestoreThread
  3 461045         PyNumber_Remainder:entry PyNumber_Remainder
  3 461240         PyFloat_FromDouble:entry PyFloat_FromDouble
...
```

On Linux this does roughly the same thing:

```sh
sudo bpftrace -p $(pgrep python3) -e 'u:/usr/bin/python3:PyEval*{print(func)}'
```

```
Attaching 24 probes...
PyEval_RestoreThread
PyEval_SaveThread
PyEval_RestoreThread
PyEval_SaveThread
PyEval_RestoreThread
...
```

Specifying `u:/usr/bin/python3:Py*` would be better tends to exceed what
bpftrace is capable of.

Note: The `$(pgrep python3)` is not actually needed but I leave it in the
example to remind that it's possible to target a specific python process.
