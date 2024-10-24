

def inner(a):
    a *= 2  # <---
    return a


def outer():
    for i in range(100):
        inner(i % 8)


def main():
    outer()


if __name__ == '__main__':
    main()
