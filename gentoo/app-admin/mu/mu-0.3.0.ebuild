# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

RUST_MIN_VER="1.85.0"
CRATES=""

inherit cargo

DESCRIPTION="Minimal privilege escalation runner for Gentoo"
HOMEPAGE="https://github.com/MulpinKR/mu"
SRC_URI="
	https://github.com/MulpinKR/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz
	${CARGO_CRATE_URIS}
"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64"

DEPEND="virtual/libcrypt:="
RDEPEND="${DEPEND}"

QA_FLAGS_IGNORED="usr/sbin/mu"

src_install() {
	cargo_src_install
	mkdir -p "${D}/usr/sbin" || die
	mv "${D}/usr/bin/mu" "${D}/usr/sbin/mu" || die
}
