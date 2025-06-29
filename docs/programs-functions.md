# Functions

A number of utility functions are made available in probe context to facilitate
common debugging and tracing scenarios.
These functions are divided up into two kinds, standard functions and
aggregation functions.

## Standard Functions

| Function | Description |
|----------|-------------|
| `print(arg1, arg2, ...)` | Works just like the python `print` builtin, except that it sends the output back to the tracer. It intentionally shadows the `print` builtin so that it's easier to debug than to accidently cause observable behaviour in the target. |
| `funcname()` | Returns the name of the function in which the probe hit. |
| `qualname()` | Returns the full module-qualified name of the function. |
| `args()` | Returns a dictionary containing the current function's arguments. |
| `exit()` | Ends tracing. |


## Aggregation Functions

Aggregation functions are special and must be assigned to
pymontrace variables or into map entries.

| Function | Description |
|----------|-------------|
| `agg.count()` | Counts the number of times it is called. |
| `agg.sum(arg)` | Adds `arg` to the sum. |
| `agg.max(arg)` | Computes the maximum over supplied arguments. |
| `agg.min(arg)` | Computes the minimum over supplied arguments. |
| `agg.quantize(arg: int \| float)` | Counts its arguments into power of 2 sized buckets and displays a histogram. |
