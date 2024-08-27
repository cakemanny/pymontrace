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

setup(
    ext_modules=[
        Extension(
            name="pymontrace.attacher",
            sources=sources,
        )
    ]
)
