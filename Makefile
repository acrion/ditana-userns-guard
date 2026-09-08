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

check: all
	tests/run-tests

clean:
	rm -rf $(BUILD)

.PHONY: all install check clean
