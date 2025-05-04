#!/bin/bash

target=$(pgrep '[Pp]ython')

for _ in {1..100}; do
    if ! kill -0 "$target"; then
        exit;
    fi
    pymontrace -p "$target" -e 'line:*lots.py:8 {{ print(ctx.msg, end="") }}' &
    sleep 0.1
    kill $!
    wait
done
