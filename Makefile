# Copyright (c) 2020 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

SHELL := bash # the shell used internally by Make

# used inside the included makefiles
BUILD_SYSTEM_DIR := vendor/nimbus-build-system

# -d:insecure - Necessary to enable Prometheus HTTP endpoint for metrics
# -d:chronicles_colors:none - Necessary to disable colors in logs for Docker
DOCKER_IMAGE_NIM_PARAMS ?= -d:chronicles_colors:none -d:insecure

LINK_PCRE := 0

# we don't want an error here, so we can handle things later, in the ".DEFAULT" target
-include $(BUILD_SYSTEM_DIR)/makefiles/variables.mk

.PHONY: \
	all \
	clean \
	coverage \
	deps \
	libbacktrace \
	test \
	update

ifeq ($(NIM_PARAMS),)
# "variables.mk" was not included, so we update the submodules.
GIT_SUBMODULE_UPDATE := nimble install https://github.com/elcritch/atlas && atlas rep --noexec atlas.lock
.DEFAULT:
	+@ echo -e "Git submodules not found. Running '$(GIT_SUBMODULE_UPDATE)'.\n"; \
		$(GIT_SUBMODULE_UPDATE); \
		echo
# Now that the included *.mk files appeared, and are newer than this file, Make will restart itself:
# https://www.gnu.org/software/make/manual/make.html#Remaking-Makefiles
#
# After restarting, it will execute its original goal, so we don't have to start a child Make here
# with "$(MAKE) $(MAKECMDGOALS)". Isn't hidden control flow great?

else # "variables.mk" was included. Business as usual until the end of this file.

# default target, because it's the first one that doesn't start with '.'

# Builds the codex binary
all: | build deps
	echo -e $(BUILD_MSG) "$@" && \
		$(ENV_SCRIPT) nim test $(NIM_PARAMS)

# must be included after the default target
-include $(BUILD_SYSTEM_DIR)/makefiles/targets.mk

deps: | deps-common nat-libs

#- deletes and recreates "codexdht.nims" which on Windows is a copy instead of a proper symlink
update: | update-common
	rm -rf codexdht.nims && \
		$(MAKE) codexdht.nims $(HANDLE_OUTPUT)

# Builds and run a part of the test suite
test: | build deps
	echo -e $(BUILD_MSG) "$@" && \
		$(ENV_SCRIPT) nim test $(NIM_PARAMS) config.nims

# usual cleaning
clean: | clean-common

endif # "variables.mk" was not included
