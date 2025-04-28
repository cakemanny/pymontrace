#!/bin/sh

if [ "$(uname)" = "Linux" ]; then
         pymontrace -p "$(pgrep '[Pp]ython')" -e 'line:*/script_to_debug.py:13 {{ print("a", ctx.a, "b", ctx.b) }}'
else
    sudo pymontrace -p "$(pgrep '[Pp]ython')" -e 'line:*/script_to_debug.py:13 {{ print("a", ctx.a, "b", ctx.b) }}'
fi
