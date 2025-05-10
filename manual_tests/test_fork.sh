#!/bin/bash

#
# For some reason it doesn't happen in the pytest tests but
# roughly half the time the PTRACE_EVENT_STOP happens first in the child
# before the PTRACE_EVENT_FORK happens in the parent...
#
# Running this was able to find a bug until in the handling of this
# scenario before it was fixed.
#

python3 -c 'import os, time, signal;
time.sleep(1)
if os.fork() == 0:
  print("hi")
  time.sleep(0.1)
  print("child")
else:
  print("ho")
  time.sleep(0.1)
  print("parent")
  child, wstatus = os.wait()
  exit_code = os.waitstatus_to_exitcode(wstatus)
  print(child, exit_code if exit_code >= 0 else signal.strsignal(-exit_code))
  exit(exit_code)
' &

pymontrace -p $! -e 'func::start {{ print(qualname()) }}'

wait
