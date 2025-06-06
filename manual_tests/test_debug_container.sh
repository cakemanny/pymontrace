#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")/.."

# This simulates the relationship between a normal container and a kubectl
# debug container.

python3 setup.py sdist

image_id=$(docker build -q -f - <<'EOF' .
FROM python:3.12
WORKDIR /src
COPY dist/pymontrace-*.tar.gz .
RUN pip install pymontrace-*.tar.gz
EOF
)

cid=$(docker run --detach --rm python:3.12 bash -c "
python3 -u -c 'import time;
start = time.time()
a = 0
def fff(a):
    a += 1
    return a
while time.time() - start < 3:
    a = fff(a)
    time.sleep(0.1)
'
sleep 1  # give the trace container time to complete otherwise its SIGKILLed
"
)

docker run --rm -i -w /src --pid="container:$cid" "$image_id" bash <<'EOF'
export PYTHONUNBUFFERED=1
pymontrace -p "$(pgrep python)" -e 'pymontrace::BEGIN {{ print("hi") }} func:*.fff:return {{ print(ctx.a) }} pymontrace::END {{ print("bye") }}'
EOF

docker image rm "$image_id"
