SHELL := /bin/sh

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
VERSION ?= $(shell "$(ROOT)/packaging/version.sh")
ARTIFACT_DIR ?= $(ROOT)/dist
BINARY ?= $(ROOT)/target/release/pathchord

.PHONY: help version package-deb package-alpine package-arch package-freebsd package-windows clean

help:
	@printf '%s\n' \
	  'PathChord package targets:' \
	  '  make package-deb     Build a Debian package from target/release/pathchord' \
	  '  make package-alpine  Build an Alpine APK with abuild' \
	  '  make package-arch    Build an Arch package with makepkg' \
	  '  make package-freebsd Build a FreeBSD pkg from the port skeleton' \
	  '  make package-windows Build a Windows NSIS installer with makensis' \
	  '' \
	  'Set BINARY to a prebuilt target binary when the host cannot build that target.'

version:
	@printf '%s\n' '$(VERSION)'

package-deb:
	@mkdir -p "$(ARTIFACT_DIR)"
	@PATHCHORD_VERSION='$(VERSION)' PATHCHORD_BINARY='$(BINARY)' \
	  "$(ROOT)/packaging/debian/build.sh" "$(ARTIFACT_DIR)"

package-alpine:
	@mkdir -p "$(ARTIFACT_DIR)"
	@PATHCHORD_VERSION='$(VERSION)' PATHCHORD_BINARY='$(BINARY)' \
	  "$(ROOT)/packaging/alpine/build.sh" "$(ARTIFACT_DIR)"

package-arch:
	@mkdir -p "$(ARTIFACT_DIR)"
	@PATHCHORD_VERSION='$(VERSION)' PATHCHORD_BINARY='$(BINARY)' \
	  "$(ROOT)/packaging/arch/build.sh" "$(ARTIFACT_DIR)"

package-freebsd:
	@mkdir -p "$(ARTIFACT_DIR)"
	@PATHCHORD_VERSION='$(VERSION)' PATHCHORD_BINARY='$(BINARY)' \
	  "$(ROOT)/packaging/freebsd/build.sh" "$(ARTIFACT_DIR)"

package-windows:
	@powershell -NoProfile -ExecutionPolicy Bypass -File \
	  "$(ROOT)/packaging/windows/build.ps1" -Version '$(VERSION)' \
	  -Binary '$(BINARY)' -OutputDirectory '$(ARTIFACT_DIR)'

clean:
	rm -rf "$(ARTIFACT_DIR)"
