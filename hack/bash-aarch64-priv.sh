#!/bin/sh

exec docker run -it --rm -v "$PWD:/src" -w /src --pid=host --privileged \
    --platform=linux/arm64/v8 python:3.11 \
    bash "$@"
