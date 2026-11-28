.if !defined(PATHCHORD_ROLE) || (${PATHCHORD_ROLE} != "ingress" && ${PATHCHORD_ROLE} != "egress")
.error Set PATHCHORD_ROLE=ingress or PATHCHORD_ROLE=egress
.endif
PORTNAME=       pathchord-${PATHCHORD_ROLE}d
.if !defined(DISTVERSION)
.if !empty(PATHCHORD_VERSION)
DISTVERSION=    ${PATHCHORD_VERSION}
.elif exists(${.PARSEDIR}/../version.sh)
DISTVERSION!=   sh ${.PARSEDIR:Q}/../version.sh
.else
.error Set PATHCHORD_VERSION when building a standalone port
.endif
.endif
.if empty(DISTVERSION:M[0-9]*) || !empty(DISTVERSION:C/[0-9A-Za-z.+_-]//g)
.error Invalid package version
.endif
CATEGORIES=     net security
USE_GITHUB=     yes
GH_ACCOUNT=     KagurazakaNyaa
GH_PROJECT=     PathChord
GH_TAGNAME=     v${DISTVERSION}
MAINTAINER=     PathChord contributors <pathchord@example.invalid>
COMMENT=        PathChord ${PATHCHORD_ROLE} runtime and management client
WWW=            https://github.com/KagurazakaNyaa/PathChord
LICENSE=        GPLv3
LICENSE_FILE=   ${WRKSRC}/LICENSE
USES=           cargo
PKGINSTALL=     ${WRKSRC}/packaging/freebsd/pkg-install
PKGDEINSTALL=   ${WRKSRC}/packaging/freebsd/pkg-deinstall
CARGO_BUILD_ARGS= --bin ${PORTNAME} --bin pathchordctl
CARGO_INSTALL_PATH= crates/${PORTNAME} crates/pathchordctl
PLIST_SUB=      ROLE=${PATHCHORD_ROLE} DAEMON=${PORTNAME}
.if ${PATHCHORD_ROLE} == "ingress"
CONFLICTS_INSTALL= pathchord-egressd pathchord
ROLE_TEMPLATE=  default-config.yaml
.else
CONFLICTS_INSTALL= pathchord-ingressd pathchord
ROLE_TEMPLATE=  default-egress-config.yaml
.endif
post-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/pathchord/${PATHCHORD_ROLE} \
		${STAGEDIR}${PREFIX}/etc/rc.d ${STAGEDIR}${PREFIX}/libexec \
		${STAGEDIR}${PREFIX}/share/licenses/${PORTNAME} ${STAGEDIR}${PREFIX}/share/man/man1
	${INSTALL_DATA} ${WRKSRC}/LICENSE ${STAGEDIR}${PREFIX}/share/licenses/${PORTNAME}/LICENSE
	${SED} -e 's@/var/lib/pathchord-@/var/db/pathchord-@g' -e 's@/run/pathchord/@/var/run/pathchord/@g' \
		${WRKSRC}/packaging/common/${ROLE_TEMPLATE} > \
		${STAGEDIR}${PREFIX}/etc/pathchord/${PATHCHORD_ROLE}/${PATHCHORD_ROLE}.yaml.sample
	${INSTALL_DATA} ${WRKSRC}/packaging/common/pathchord.1 ${STAGEDIR}${PREFIX}/share/man/man1/pathchord.1
	${MKDIR} ${STAGEDIR}${PREFIX}/share/man/zh_CN/man1
	${INSTALL_DATA} ${WRKSRC}/packaging/common/pathchord.zh-CN.1 ${STAGEDIR}${PREFIX}/share/man/zh_CN/man1/pathchord.1
	${INSTALL_SCRIPT} ${WRKSRC}/packaging/common/setup-layout.sh ${STAGEDIR}${PREFIX}/libexec/pathchord-setup-layout
	${INSTALL_SCRIPT} ${WRKSRC}/packaging/freebsd/${PORTNAME}.in ${STAGEDIR}${PREFIX}/etc/rc.d/${PORTNAME}
.include <bsd.port.mk>
