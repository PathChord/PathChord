SHELL := /bin/sh
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
ROLE ?= $(PATHCHORD_ROLE)
VERSION ?= $(shell "$(ROOT)/packaging/version.sh")
ARTIFACT_DIR ?= $(ROOT)/dist
INGRESS_BINARY ?= $(if $(PATHCHORD_INGRESS_BINARY),$(PATHCHORD_INGRESS_BINARY),$(ROOT)/target/release/pathchord-ingressd)
EGRESS_BINARY ?= $(if $(PATHCHORD_EGRESS_BINARY),$(PATHCHORD_EGRESS_BINARY),$(ROOT)/target/release/pathchord-egressd)
DAEMON_BINARY ?= $(if $(filter ingress,$(ROLE)),$(INGRESS_BINARY),$(EGRESS_BINARY))
CTL_BINARY ?= $(if $(PATHCHORDCTL_BINARY),$(PATHCHORDCTL_BINARY),$(ROOT)/target/release/pathchordctl)
.PHONY: help version check-role package-deb package-alpine package-arch package-freebsd package-windows clean
help:
	@printf '%s\n' 'Select ROLE=ingress or ROLE=egress.' \
	  'make ROLE=ingress package-deb|package-alpine|package-arch|package-freebsd|package-windows' \
	  'Only the selected daemon and pathchordctl are packaged.'
version:
	@printf '%s\n' '$(VERSION)'
check-role:
	@case '$(ROLE)' in ingress|egress) ;; *) echo 'set ROLE=ingress or ROLE=egress' >&2; exit 2;; esac
package-deb package-alpine package-arch package-freebsd: check-role
	@mkdir -p "$(ARTIFACT_DIR)"
	@PATHCHORD_ROLE='$(ROLE)' PATHCHORD_VERSION='$(VERSION)' PATHCHORD_DAEMON_BINARY='$(DAEMON_BINARY)' PATHCHORDCTL_BINARY='$(CTL_BINARY)' \
	  "$(ROOT)/packaging/$(if $(filter package-deb,$@),debian,$(patsubst package-%,%,$@))/build.sh" "$(ARTIFACT_DIR)"
package-windows: check-role
	@powershell -NoProfile -ExecutionPolicy Bypass -File "$(ROOT)/packaging/windows/build.ps1" \
	  -Role '$(ROLE)' -Version '$(VERSION)' -DaemonBinary '$(DAEMON_BINARY)' \
	  -CtlBinary '$(CTL_BINARY)' -OutputDirectory '$(ARTIFACT_DIR)'
clean:
	rm -rf "$(ARTIFACT_DIR)"
