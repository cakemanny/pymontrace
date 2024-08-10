#!/bin/sh

if [ "$(uname)" = "Linux" ]; then
         python3 -m pymontrace -p "$(pgrep '[Pp]ython')" line:examples/script_to_debug.py:13 'print("a", a, "b", b)'
else
    sudo python3 -m pymontrace -p "$(pgrep '[Pp]ython')" line:examples/script_to_debug.py:13 'print("a", a, "b", b)'
fi
