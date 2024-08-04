import time


def f(sleeper, a, b):
    while True:
        sleeper((a + b) / 4, a, b)
        a, b = b, a + b
        b = b % 9


def g(sleep_duration, a, b):

    time.sleep(sleep_duration)


def main():
    f(g, 1, 1)


if __name__ == '__main__':
    main()
