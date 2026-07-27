# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cargo

DESCRIPTION="Minimal privilege escalation runner — an alternative to sudo/doas"
HOMEPAGE="https://github.com/MulpinKR/mu"
SRC_URI="https://github.com/MulpinKR/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64"

DEPEND=""
RDEPEND=""
BDEPEND="virtual/rust"

QA_FLAGS_IGNORED="usr/bin/mu"

src_install() {
	cargo_src_install
}

pkg_postinst() {
	einfo ""
	einfo "mu needs the setuid bit to function:"
	einfo "  # chown root:root /usr/bin/mu"
	einfo "  # chmod u+s /usr/bin/mu"
	einfo ""
}
