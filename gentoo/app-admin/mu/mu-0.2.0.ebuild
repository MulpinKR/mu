# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cargo

DESCRIPTION="Minimal privilege escalation runner with password auth, audit log, and brute-force protection"
HOMEPAGE="https://github.com/MulpinKR/mu"
SRC_URI="https://github.com/MulpinKR/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64"

DEPEND=""
RDEPEND=""
BDEPEND="virtual/rust"

QA_FLAGS_IGNORED="usr/sbin/mu"

src_install() {
	cargo_src_install
	mv "${D}/usr/bin/mu" "${D}/usr/sbin/mu" || die
}

pkg_postinst() {
	einfo ""
	einfo "mu needs the setuid bit to function:"
	einfo "  # chown root:root /usr/sbin/mu"
	einfo "  # chmod u+s /usr/sbin/mu"
	einfo "  # echo \"permit \$(whoami)\" > /etc/mu.conf"
	einfo ""
	einfo "Audit log: /var/log/mu.log"
	einfo ""
}
