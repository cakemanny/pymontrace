#!/bin/sh

# usage: ./hack/test-wheel <wheel_path>
#
# Used in build-and-publish workflow to verify the wheel before publishing
#

set -eu

export UV_PYTHON_DOWNLOADS=never

wheel_path=$1
test -f "$wheel_path"

for V in 3.9 3.10 3.11 3.12 3.13 3.14; do
    echo "::group::$(python${V} -VV)"
    rm -rf .venv
    uv venv -p ${V}
    # shellcheck disable=SC1091
    . .venv/bin/activate
    uv pip install pytest "$wheel_path"
    pytest integration_tests/
    deactivate
    echo "::endgroup::"
done
