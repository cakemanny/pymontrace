#!/usr/bin/env bash

if [[ $(uname) == "Darwin" ]] || [[ -f "/proc/sys/kernel/yama" && $(cat /proc/sys/kernel/yama) != "0" ]]; then
    SUDO=sudo
    sudo -v
else
    SUDO=""
fi

python3 <<EOF &
import time

def f():
    time.sleep(0.2)

for _ in range(10):
    f()
print("traced: bye!")
EOF

target_pid=$!

# This example should show the printing of maps and the executing of
# the END probe for processes that end normally.
#
# Expected output ends with
#   traced: bye!
#   tracer: bye bye
#   @
#
#       f: 8

$SUDO pymontrace -p $target_pid -e '
func:f:start {{
    maps[funcname()] = agg.count()
}}

pymontrace::END {{
    print("tracer: bye bye")
}}
'
