#!/bin/bash

target=$(pgrep '[Pp]ython')

for _ in {1..100}; do
    if ! kill -0 "$target"; then
        exit;
    fi
    pymontrace -p "$target" 'line:*lots.py:8' 'pmt.print(msg, end="")' &
    sleep 0.1
    kill $!
    wait
done
