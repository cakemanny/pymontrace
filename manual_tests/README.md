# Manual Tests

Ideally these will become integration tests or stress tests

## `mt_spawn_lots.py` + `repeat_attach_abuse.sh`

This tests attaching to a process which is feverishly spawning new threads.
The desired outcome is that the target process remains intact and is most of
the time successfully attached to.

Assuming no other python processes running on the box,

Terminal 1

    python3 mt_spawn_lots.py

Terminal 2

    ./repeat_attach_abuse.sh
    # or on macOS
    sudo ./repeat_attach_abuse.sh


## `mt_to_debug.py`

This checks that probes are attached to all threads in the target process.
It's probably already tested in one of the unit tests for the attacher module.

Expected outcome: both "fizz" and "buzz" messages are printed; "fizzbuzz" not.

Terminal 1

    python3 mt_to_debug.py

Terminal 2

    pymontrace -p $(pgrep python) -e 'line:*debug.py:8 {{ print(ctx.msg, end="") }}'
    # or on macOS
    sudo pymontrace -p $(pgrep Python) -e 'line:*debug.py:8 {{ print(ctx.msg, end="") }}'


## `threaded_server.py`

He we want to check that probes attach to newly spawned threads.

Terminal 1

    python3 threaded_server.py

Terminal 2

    pymontrace -p "$(pgrep python)" -e 'line:*server.py:16 {{ print(ctx.self) }}'
    # or on macOS
    sudo pymontrace -p "$(pgrep Python)" -e 'line:*server.py:16 {{ print(ctx.self) }}'

Terminal 3

    for i in {1..3}; do curl http://127.0.0.1:8000/; done
