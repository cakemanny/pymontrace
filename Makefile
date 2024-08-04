

.PHONY: dev-setup
dev-setup:
	test -n "$$VIRTUAL_ENV"
	"$$VIRTUAL_ENV"/bin/pip install uv
	"$$VIRTUAL_ENV"/bin/uv pip install -e '.[dev,test]'
