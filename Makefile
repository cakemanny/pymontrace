OS = $(shell uname)

.PHONY: dev-setup
dev-setup:
	test -n "$$VIRTUAL_ENV"
	type uv || "$$VIRTUAL_ENV"/bin/pip install uv
	uv pip install -e '.[dev,test]'


.PHONY: lint
lint:
	flake8 src


.PHONY: check
ifeq "$(OS)" "Darwin"
# Pre-flight the linux code when working on mac
check:
	cc -c -target x86_64-apple-macos10.13 -Wall -Wsign-compare -Werror -o /dev/null c_src/darwin_64bit.c
	./hack/bash-aarch64.sh -c 'make check'

else

CFLAGS = -Wall -Wsign-compare -Wvla -Werror
check:
	$(CC) -fsyntax-only $(CFLAGS) c_src/attacher_linux_64bit.c
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
