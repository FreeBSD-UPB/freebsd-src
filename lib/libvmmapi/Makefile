# $FreeBSD$

PACKAGE=lib${LIB}
LIB=	vmmapi
SRCS=	vmmapi.c vmmapi_freebsd.c
INCS=	vmmapi.h

WARNS?=	2

.if exists(${LIB_SRCTOP}/${MACHINE})
LIB_ARCH=	${MACHINE}
.elif exists(${LIB_SRCTOP}/${MACHINE_ARCH})
LIB_ARCH=	${MACHINE_ARCH}
.else
LIB_ARCH=	${MACHINE_CPUARCH}
.endif

CFLAGS+= -I${.CURDIR}

.include <bsd.lib.mk>
