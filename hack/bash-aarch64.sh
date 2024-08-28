#!/bin/sh

exec docker run -it --rm \
    -v apt_lists:/var/lib/apt/lists \
    -v apt_cache:/var/cache/apt \
    -v /dev/null:/etc/apt/apt.conf.d/docker-clean \
    -v "$PWD:/src" \
    -w /src \
    --platform=linux/arm64/v8 \
    python:3.12 \
    bash "$@"
