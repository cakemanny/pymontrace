# Special Variables

There are a couple of variables that act as namespaces for storing data
between the executions of probe actions.

| Variable | Description |
|----------|-------------|
| `vars`   | `vars` is a namespace for holding user variables. This can be used to store values between probe executions. |
| `maps`   | `maps` is a namespace for holding user maps (dictionaries). Any non-empty maps will printed out at the end of tracing. They are most useful when combined with aggregations. `maps` itself behaves like an dictionary with the name `@`. |
