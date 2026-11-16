PORTNAME=       pathchord
DISTVERSION?=   0.1.0
CATEGORIES=     net security
USE_GITHUB=     yes
GH_ACCOUNT=     KagurazakaNyaa
GH_PROJECT=     PathChord
GH_TAGNAME=     v${DISTVERSION}

MAINTAINER=     PathChord contributors <pathchord@example.invalid>
COMMENT=        Adaptive multipath proxy runtime with HTTP and SOCKS listeners
WWW=            https://github.com/KagurazakaNyaa/PathChord

LICENSE=        GPLv3
LICENSE_FILE=   ${WRKSRC}/LICENSE

USES=           cargo
USERS=          pathchord
GROUPS=         pathchord

CARGO_BUILD_ARGS= --bin pathchord-ingressd --bin pathchord-egressd --bin pathchordctl

post-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/pathchord/ingress \
		${STAGEDIR}${PREFIX}/etc/pathchord/egress \
		${STAGEDIR}/var/db/pathchord-ingress \
		${STAGEDIR}/var/db/pathchord-egress \
		${STAGEDIR}${PREFIX}/etc/rc.d \
		${STAGEDIR}${PREFIX}/share/licenses/pathchord \
		${STAGEDIR}${PREFIX}/share/man/man1 \
		${STAGEDIR}${PREFIX}/share/pathchord
	${INSTALL_DATA} ${WRKSRC}/LICENSE \
		${STAGEDIR}${PREFIX}/share/licenses/pathchord/LICENSE
	${INSTALL_DATA} ${WRKSRC}/packaging/common/default-config.yaml \
		${STAGEDIR}${PREFIX}/etc/pathchord/ingress/ingress.yaml
	${INSTALL_DATA} ${WRKSRC}/packaging/common/pathchord.1 \
		${STAGEDIR}${PREFIX}/share/man/man1/pathchord.1
	${INSTALL_SCRIPT} ${WRKSRC}/packaging/freebsd/pathchord.in \
		${STAGEDIR}${PREFIX}/etc/rc.d/pathchord
	${INSTALL_SCRIPT} ${WRKSRC}/packaging/freebsd/pathchord-egress.in \
		${STAGEDIR}${PREFIX}/etc/rc.d/pathchord-egress
	${SED} 's,%%PREFIX%%,${PREFIX},g' \
		${WRKSRC}/packaging/freebsd/pkg-message > \
		${STAGEDIR}${PREFIX}/share/pathchord/pkg-message

.include <bsd.port.mk>
