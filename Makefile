

.PHONY: dev-setup
dev-setup:
	test -n "$$VIRTUAL_ENV"
	type uv || "$$VIRTUAL_ENV"/bin/pip install uv
	uv pip install -e '.[dev,test]'


.PHONY: lint
lint:
	flake8 src


# Pre-flight the linux code when working on mac
.PHONY: check
check:
	cc -target x86_64-apple-macos10.13 -fsyntax-only -Wall c_src/darwin_64bit.c
	./hack/bash-aarch64.sh -c 'cc -fsyntax-only -Wall -Werror c_src/attacher_linux_64bit.c'
	./hack/bash-aarch64.sh -c 'apt update; apt install --yes gcc-x86-64-linux-gnu; x86_64-linux-gnu-gcc -fsyntax-only -Wall -Werror c_src/attacher_linux_64bit.c'
	./hack/bash-aarch64.sh -c 'apt update; apt install --yes gcc-riscv64-linux-gnu; riscv64-linux-gnu-gcc -fsyntax-only -Wall -Werror c_src/attacher_linux_64bit.c'
	#./hack/bash-amd64.sh -c 'cc -fsyntax-only -Wall -Werror c_src/attacher_linux_64bit.c'


# Note, it's not possible to do the amd64 test with docker on mac because
# qemu runs in user space in an arm64 VM there.
.PHONY: test
test:
	./hack/bash-aarch64.sh -c 'pip install .; python3 examples/script_to_debug.py & sleep 1; ./hack/example.sh'
