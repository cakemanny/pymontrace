OS = $(shell uname)

PIP ?= uv pip

.PHONY: dev-setup
dev-setup:
	test -n "$$VIRTUAL_ENV"
	type uv || "$$VIRTUAL_ENV"/bin/pip install uv
	$(PIP) install -e '.[dev,test]' setuptools


.PHONY: lint
lint:
	flake8 src
	pyright src
	isort src --check --diff


TO_CHECK = c_src/attachermodule.c c_src/mapbuffermodule.c

.PHONY: check
ifeq "$(OS)" "Darwin"

TO_CHECK += c_src/darwin_64bit.c
PY_INCLUDE := $(shell python3 -c 'import sysconfig; print(sysconfig.get_path("include"), end="")')
CFLAGS = -Wall -Wsign-compare -Wvla -Werror -I$(PY_INCLUDE)

# Pre-flight the linux code when working on mac
check:
	set -eu; for F in $(TO_CHECK); do \
		cc -c -target x86_64-apple-macos10.13 $(CFLAGS) -o /dev/null $$F; \
	done
	./hack/bash-aarch64.sh -c 'make check'

else

TO_CHECK += c_src/attacher_linux_64bit.c
PY_INCLUDE := $(shell python3 -c 'import sysconfig; print(sysconfig.get_path("include"), end="")')

CFLAGS = -Wall -Wsign-compare -Wvla -Werror -I$(PY_INCLUDE)
check:
	set -eu; for F in $(TO_CHECK); do \
		$(CC) -fsyntax-only $(CFLAGS) $$F; \
	done
	type riscv64-linux-gnu-gcc || apt update
	type riscv64-linux-gnu-gcc || \
		apt install --yes \
			gcc-aarch64-linux-gnu \
			gcc-x86-64-linux-gnu \
			gcc-riscv64-linux-gnu
	aarch64-linux-gnu-gcc -fsyntax-only $(CFLAGS) c_src/attacher_linux_64bit.c
	x86_64-linux-gnu-gcc -fsyntax-only $(CFLAGS) c_src/attacher_linux_64bit.c
	riscv64-linux-gnu-gcc -fsyntax-only $(CFLAGS) c_src/attacher_linux_64bit.c

endif # OS eq Darwin

# Note, it's not possible to do the amd64 test with docker on mac because
# qemu runs in user space in an arm64 VM there.
.PHONY: test
test:
	./hack/bash-aarch64.sh -c 'pip install .; python3 examples/script_to_debug.py & sleep 1; ./hack/example.sh'


.PHONY: build
build:
	$(PIP) install --upgrade build twine
	python3 -m build

.PHONY: publish
publish: build
	twine upload dist/*

.PHONY: clean
clean:
	rm -rf build/ dist/ src/pymontrace.egg-info/
