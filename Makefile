# SPDX-License-Identifier: AGPL-3.0-or-later
PREFIX      ?= /usr
DESTDIR     ?=
CLANG       ?= clang
ARCH        := x86

# makepkg unpacks every source into one flat directory, so the inputs are
# variables rather than fixed paths. The defaults are the repository layout,
# where the compiled sources sit at the top rather than in a src/ of their own:
# makepkg's $srcdir is always $startdir/src, and a repository that keeps its
# sources there gets them replaced by symlinks into the makepkg cache the first
# time anyone builds the package in place.
SRC         ?= .
UNIT        ?= systemd/ditana-userns-guard.service
HOOK        ?= hooks/90-ditana-userns-guard.hook

BUILD       ?= build
OBJ         := $(BUILD)/userns_guard.bpf.o
BIN         := $(BUILD)/ditana-userns-guard

all: $(OBJ) $(BIN)

$(BUILD):
	mkdir -p $(BUILD)

# No vmlinux.h and therefore no bpftool at build time: src/kernel_types.h
# declares the six structures this program reads, and CO-RE resolves their
# offsets against the kernel that loads it. See the comment in that file.
$(OBJ): $(SRC)/userns_guard.bpf.c $(SRC)/kernel_types.h | $(BUILD)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(SRC) -c $< -o $@
	llvm-strip -g $@

$(BIN): $(SRC)/userns-guard.c | $(BUILD)
	$(CLANG) -O2 -Wall -Wextra -o $@ $< -lbpf

install: all
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/ditana-userns-guard
	install -Dm644 $(OBJ) $(DESTDIR)$(PREFIX)/lib/ditana/userns_guard.bpf.o
	install -Dm644 $(UNIT) $(DESTDIR)$(PREFIX)/lib/systemd/system/ditana-userns-guard.service
	install -Dm644 $(HOOK) $(DESTDIR)$(PREFIX)/share/libalpm/hooks/90-ditana-userns-guard.hook
# The directory, so that writing the allowlist by hand needs no mkdir. The
# documented way to switch the guard on ends in `| sudo tee
# /etc/ditana/userns-allow.conf`, and tee creates the file but never the
# directory above it. The installer creates /etc/ditana only where it also
# writes a list, so a machine whose sandboxes broke for want of one never got
# the directory either -- and that is exactly the machine whose owner is
# following these instructions. The error they meet is
# `tee: No such file or directory`.
#
# An empty directory, and deliberately so: ConditionPathExists on the allowlist
# is what switches the unit on, so a file shipped here would enable the guard
# on every machine that updates.
	install -dm755 $(DESTDIR)/etc/ditana

check: all
	tests/install-test
	tests/unprivileged-test
	tests/refusal-test
	tests/run-tests

clean:
	rm -rf $(BUILD)

.PHONY: all install check clean
