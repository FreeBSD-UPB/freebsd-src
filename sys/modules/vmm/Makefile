# $FreeBSD$

.include <kmod.opts.mk>

KMOD=	vmm

SRCS=	opt_acpi.h opt_ddb.h device_if.h bus_if.h pci_if.h pcib_if.h acpi_if.h

CFLAGS+= -DVMM_KEEP_STATS
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/io
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/intel
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/amd

.include <bsd.arch.inc.mk>

.include <bsd.kmod.mk>
