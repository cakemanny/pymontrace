import os
import threading
import time


def emit_and_sleep(msg):
    os.write(1, msg.encode())
    time.sleep(0.5)


def task(msg):
    while True:
        emit_and_sleep(str(threading.get_native_id()) + ' ' + msg)


t1 = threading.Thread(target=task, args=("fizz\n",))
t2 = threading.Thread(target=task, args=("buzz\n",))

t1.start()
t2.start()

while True:
    os.write(1, (str(threading.get_native_id()) + ' ' + "fizzbuzz\n").encode())
    time.sleep(10)

t1.join()
t2.join()
