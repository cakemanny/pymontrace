import os
import threading
import time


def emit_and_sleep(msg):
    os.write(1, msg.encode())
    time.sleep(0.01)


def task(msg):
    emit_and_sleep(str(threading.get_native_id()) + ' ' + msg)


while True:
    os.write(1, (str(threading.get_native_id()) + ' ' + "fizzbuzz\n").encode())
    t1 = threading.Thread(target=task, args=("fizz\n",))
    t1.start()
    time.sleep(0.01)
    t1.join()
