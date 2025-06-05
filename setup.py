import os
import sys
from setuptools import Extension, setup

DARWIN_SOURCES = [
    "c_src/darwin_64bit.c",
    "c_src/mach_excServer.c",
]

LINUX_SOURCES = [
    "c_src/attacher_linux_64bit.c",
]

sources = [
    "c_src/attachermodule.c",
]
if sys.platform == 'darwin':
    sources += DARWIN_SOURCES
elif sys.platform == 'linux':
    sources += LINUX_SOURCES
else:
    print(sys.platform, 'is not currently supported...', file=sys.stderr)

# Undefining NDEBUG enables some debug logging.
undef_macros = []
if os.getenv("PYMONTRACE_DEBUG") in ("1", "true", "True", "yes"):
    undef_macros = ["NDEBUG"]

setup(
    ext_modules=[
        Extension(
            name="pymontrace.attacher",
            sources=sources,
            undef_macros=undef_macros,
            py_limited_api=True,
        ),
        Extension(
            name="pymontrace._tracebuffer",
            sources=["c_src/_tracebuffermodule.c"],
            undef_macros=undef_macros,
            py_limited_api=True,
        ),
    ],
    # https://github.com/pypa/setuptools/issues/4741
    options={'bdist_wheel': {'py_limited_api': 'cp39'}},
)
