# Maintainer: Stefan Zipproth <s.zipproth@ditana.org>

pkgname=ditana-userns-guard
pkgver=1.00
pkgrel=1
pkgdesc="Restrict unprivileged user namespaces to executables that declared they need them"
arch=(x86_64)
url="https://github.com/acrion/ditana-userns-guard"
license=('AGPL-3.0-or-later AND GPL-2.0-or-later')
depends=(libbpf systemd procps-ng)
makedepends=(clang llvm linux-api-headers)
source=("file://${PWD}/Makefile"
        "file://${PWD}/userns_guard.bpf.c"
        "file://${PWD}/kernel_types.h"
        "file://${PWD}/userns-guard.c"
        "file://${PWD}/systemd/ditana-userns-guard.service"
        "file://${PWD}/hooks/90-ditana-userns-guard.hook")
sha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP')

# The BPF object carries no reference to the kernel it was built against:
# kernel_types.h declares the six structures the program reads, and CO-RE
# resolves their offsets against the kernel that loads it. So this builds in a
# chroot without /sys/kernel/btf and without bpftool, and the result is not tied
# to the builder's kernel.
build() {
    cd "$srcdir"
    make SRC=.
}

package() {
    cd "$srcdir"
    make SRC=. \
         UNIT=./ditana-userns-guard.service \
         HOOK=./90-ditana-userns-guard.hook \
         DESTDIR="$pkgdir" install
}
