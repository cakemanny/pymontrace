from pymontrace.probes import END, line, func_entry


@line("*debug.py", 13)
def _(pmt, ctx):
    pmt.print("a", ctx.a, "b", ctx.b)


@func_entry("g")
def _(pmt, ctx):
    pmt.print("a", ctx.a, "b", ctx.b)


@END
def _(pmt, ctx):
    pmt.print("done")
