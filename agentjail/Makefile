.PHONY: help shim shim-clean

## help        : list available targets
help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

shim:  ## build the C PATH shim (output: ../bin/agentjail-shim)
	$(MAKE) -C native/shim build

shim-clean:  ## remove the built shim binary
	$(MAKE) -C native/shim clean
