#!/bin/sh

exec docker run -it --rm -v "$PWD:/src" -w /src --platform=linux/arm64/v8 \
    python:3.12 \
    bash "$@"
