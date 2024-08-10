#!/bin/sh

exec docker run -it --rm -v "$PWD:/src" -w /src --platform=linux/amd64 \
    python:3.12 \
    bash "$@"
