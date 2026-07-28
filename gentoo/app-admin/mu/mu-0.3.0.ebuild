# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cargo

CRATES=""

DESCRIPTION="Minimal privilege escalation runner — zero external deps, faster compile than doas"
HOMEPAGE="https://github.com/MulpinKR/mu"
SRC_URI="
	https://github.com/MulpinKR/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz
	${CARGO_CRATE_URIS}
"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64"

DEPEND=""
RDEPEND=""

QA_FLAGS_IGNORED="usr/sbin/mu"

src_install() {
	cargo_src_install
	mkdir -p "${D}/usr/sbin" || die
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
