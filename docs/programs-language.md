# The pymontrace expression language

The pymontrace language is heavily inspired by the D language of
[DTrace](https://illumos.org/books/dtrace)
and by [bpftrace](https://bpftrace.org/).

In general it follows the form


    program ::= ( probe-spec probe-action )*

    probe-spec = probe-name ":" probe-arg1 ":" probe-arg2

    probe-action = "{{" python-program-text "}}"

    probe-name = "line" | ...


Here is an example pymontrace program:

```
line:*/some-file.py:123 {{
    print("a =", ctx.a)
    if b is not None:
        vars.b = agg.count()
}}

pymontrace::END {{
    print("b =", vars.b)
}}
```


The python blocks are run in the context of the probe site.
The local and global variables are available on `ctx` and `ctx.globals`
respectively.
