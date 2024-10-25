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

TODO: add bpftrace example for Linux

