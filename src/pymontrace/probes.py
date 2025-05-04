
# These are all fake, and just for type checking?
# These could be where we write all the long complicated docs?

def line(path: str, lineno: int):
    """
    Args:
        path    The full path to the python file. Supports globbing with '*'.
                Using a prefix glob such as '*mymodule/mysubmodule.py' is
                usually a good idea.
        lineno  The line of the file to install the probe. The probe fires
                before the given line is executed.
    """

    def inner(wrapped):
        return wrapped
    return inner


def func_entry(qpath: str):
    """
    Args:
        qpath   The qualified function or method path including the module.
                Supports globbing with '*'
    """

    def inner(wrapped):
        return wrapped
    return inner


def END(wrapped=None, /):
    """
    Fires at the end of tracing.
    """
    if wrapped is not None:
        return wrapped

    def inner(wrapped):
        return wrapped
    return inner
