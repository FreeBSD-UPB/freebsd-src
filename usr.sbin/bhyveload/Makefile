# $FreeBSD$

PROG=	bhyveload
SRCS=	bhyveload.c
MAN=	bhyveload.8
PACKAGE=	bhyve

BHYVELOAD_SYSDIR?=${SRCTOP}
BHYVELOAD_SRCTOP?=${.CURDIR}

.if exists(${BHYVELOAD_SRCTOP}/${MACHINE})
BHYVELOAD_ARCH=	${MACHINE}
.elif exists(${BHYVELOAD_SRCTOP}/${MACHINE_ARCH})
BHYVELOAD_ARCH=	${MACHINE_ARCH}
.else
BHYVELOAD_ARCH=	${MACHINE_CPUARCH}
.endif

LIBADD=	vmmapi

WARNS?=	3

CFLAGS+=-I${SRCTOP}/stand/userboot

.include <bsd.prog.mk>
