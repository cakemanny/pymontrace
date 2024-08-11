

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
	./hack/bash-aarch64.sh -c 'cc -fsyntax-only -Wall -Werror c_src/attacher_linux_64bit.c'
	./hack/bash-amd64.sh -c 'cc -fsyntax-only -Wall -Werror c_src/attacher_linux_64bit.c'


# Note, it's not possible to do the amd64 test with docker on mac because
# qemu runs in user space in an arm64 VM there.
.PHONY: test
test:
	./hack/bash-aarch64.sh -c 'pip install .; python3 examples/script_to_debug.py & sleep 1; ./hack/example.sh'
