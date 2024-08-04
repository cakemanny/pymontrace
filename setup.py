import sys
from setuptools import Extension, setup

DARWIN_SOURCES = [
    "c_src/darwin_arm64.c",
    "c_src/mach_excServer.c",
]

if sys.platform != 'darwin':
    print(sys.platform, 'is not currently supported...', file=sys.stderr)

setup(
    ext_modules=[
        Extension(
            name="pymontrace.attacher",
            sources=[
                "c_src/attachermodule.c",
            ] + DARWIN_SOURCES
        )
    ]
)
