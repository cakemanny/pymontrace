
python3 -c 'import os, time, signal, threading

def task():
    print("hi")
    time.sleep(0.1)
    print("task")

t = threading.Thread(target=task)
time.sleep(1)
t.start()
print("ho")
time.sleep(0.1)
print("main")
t.join()
' &

pymontrace -p $! -e 'pymontrace::BEGIN {{ print("attached") }}'

wait
