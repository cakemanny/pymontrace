#!/bin/sh

if [ "$(uname)" = "Linux" ]; then
         pymontrace -p "$(pgrep '[Pp]ython')" -e 'line:*/script_to_debug.py:13 {{ pmt.print("a", a, "b", b) }}'
else
    sudo pymontrace -p "$(pgrep '[Pp]ython')" -e 'line:*/script_to_debug.py:13 {{ pmt.print("a", a, "b", b) }}'
fi
