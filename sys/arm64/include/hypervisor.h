/*-
 * Copyright (c) 2013, 2014 Andrew Turner
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _MACHINE_HYPERVISOR_H_
#define	_MACHINE_HYPERVISOR_H_

/*
 * These registers are only useful when in hypervisor context,
 * e.g. specific to EL2, or controlling the hypervisor.
 */

/* CNTHCTL_EL2 - Counter-timer Hypervisor Control register */
#define	CNTHCTL_EVNTI_MASK	(0xf << 4) /* Bit to trigger event stream */
#define	CNTHCTL_EVNTDIR		(1 << 3) /* Control transition trigger bit */
#define	CNTHCTL_EVNTEN		(1 << 2) /* Enable event stream */
#define	CNTHCTL_EL1PCEN		(1 << 1) /* Allow EL0/1 physical timer access */
#define	CNTHCTL_EL1PCTEN	(1 << 0) /*Allow EL0/1 physical counter access*/

/* CPTR_EL2 - Architecture feature trap register */
#define	CPTR_RES0	0x7fefc800
#define	CPTR_RES1	0x000033ff
#define	CPTR_TFP	0x00000400
#define	CPTR_TTA	0x00100000
#define	CPTR_TCPAC	0x80000000

/* HCR_EL2 - Hypervisor Config Register */
#define	HCR_VM		0x0000000000000001
#define	HCR_SWIO	0x0000000000000002
#define	HCR_PTW		0x0000000000000004
#define	HCR_FMO		0x0000000000000008
#define	HCR_IMO		0x0000000000000010
#define	HCR_AMO		0x0000000000000020
#define	HCR_VF		0x0000000000000040
#define	HCR_VI		0x0000000000000080
#define	HCR_VSE		0x0000000000000100
#define	HCR_FB		0x0000000000000200
#define	HCR_BSU_MASK	0x0000000000000c00
#define	 HCR_BSU_IS	0x0000000000000400
#define	 HCR_BSU_OS	0x0000000000000800
#define	 HCR_BSU_FS	0x0000000000000c00
#define	HCR_DC		0x0000000000001000
#define	HCR_TWI		0x0000000000002000
#define	HCR_TWE		0x0000000000004000
#define	HCR_TID0	0x0000000000008000
#define	HCR_TID1	0x0000000000010000
#define	HCR_TID2	0x0000000000020000
#define	HCR_TID3	0x0000000000040000
#define	HCR_TSC		0x0000000000080000
#define	HCR_TIDCP	0x0000000000100000
#define	HCR_TACR	0x0000000000200000
#define	HCR_TSW		0x0000000000400000
#define	HCR_TPCP	0x0000000000800000
#define	HCR_TPU		0x0000000001000000
#define	HCR_TTLB	0x0000000002000000
#define	HCR_TVM		0x0000000004000000
#define	HCR_TGE		0x0000000008000000
#define	HCR_TDZ		0x0000000010000000
#define	HCR_HCD		0x0000000020000000
#define	HCR_TRVM	0x0000000040000000
#define	HCR_RW		0x0000000080000000
#define	HCR_CD		0x0000000100000000
#define	HCR_ID		0x0000000200000000
#define	HCR_E2H		0x0000000400000000
#define	HCR_TLOR	0x0000000800000000
#define	HCR_TERR	0x0000001000000000
#define	HCR_TEA		0x0000002000000000
#define	HCR_MIOCNCE	0x0000004000000000
/* Bit 39 is reserved */
#define	HCR_APK		0x0000010000000000
#define	HCR_API		0x0000020000000000
#define	HCR_NV		0x0000040000000000
#define	HCR_NV1		0x0000080000000000
#define	HCR_AT		0x0000100000000000

/* HPFAR_EL2 - Hypervisor IPA Fault Address Register */
#define	HPFAR_EL2_FIPA_SHIFT	4
#define	HPFAR_EL2_FIPA_MASK	0xfffffffff0

/* ICC_SRE_EL2 */
#define	ICC_SRE_EL2_SRE		(1U << 0)
#define	ICC_SRE_EL2_EN		(1U << 3)

/* SCTLR_EL2 - System Control Register */
#define	SCTLR_EL2_RES1		0x30c50830
#define	SCTLR_EL2_M_SHIFT	0
#define	SCTLR_EL2_M		(0x1 << SCTLR_EL2_M_SHIFT)
#define	SCTLR_EL2_A_SHIFT	1
#define	SCTLR_EL2_A		(0x1 << SCTLR_EL2_A_SHIFT)
#define	SCTLR_EL2_C_SHIFT	2
#define	SCTLR_EL2_C		(0x1 << SCTLR_EL2_C_SHIFT)
#define	SCTLR_EL2_SA_SHIFT	3
#define	SCTLR_EL2_SA		(0x1 << SCTLR_EL2_SA_SHIFT)
#define	SCTLR_EL2_I_SHIFT	12
#define	SCTLR_EL2_I		(0x1 << SCTLR_EL2_I_SHIFT)
#define	SCTLR_EL2_WXN_SHIFT	19
#define	SCTLR_EL2_WXN		(0x1 << SCTLR_EL2_WXN_SHIFT)
#define	SCTLR_EL2_EE_SHIFT	25
#define	SCTLR_EL2_EE		(0x1 << SCTLR_EL2_EE_SHIFT)

/* TCR_EL2 - Translation Control Register */
#define	TCR_EL2_RES1		((0x1UL << 31) | (0x1UL << 23))
#define	TCR_EL2_T0SZ_SHIFT	0
#define	TCR_EL2_T0SZ_MASK	(0x3f << TCR_EL2_T0SZ_SHIFT)
#define	TCR_EL2_T0SZ(x)		((x) << TCR_EL2_T0SZ_SHIFT)
/* Bits 7:6 are reserved */
#define	TCR_EL2_IRGN0_SHIFT	8
#define	TCR_EL2_IRGN0_MASK	(0x3 << TCR_EL2_IRGN0_SHIFT)
#define	TCR_EL2_ORGN0_SHIFT	10
#define	TCR_EL2_ORGN0_MASK	(0x3 << TCR_EL2_ORGN0_SHIFT)
#define	TCR_EL2_SH0_SHIFT	12
#define	TCR_EL2_SH0_MASK	(0x3 << TCR_EL2_SH0_SHIFT)
#define	TCR_EL2_TG0_SHIFT	14
#define	TCR_EL2_TG0_MASK	(0x3 << TCR_EL2_TG0_SHIFT)
#define	TCR_EL2_PS_SHIFT	16
#define	 TCR_EL2_PS_32BITS	(0 << TCR_EL2_PS_SHIFT)
#define	 TCR_EL2_PS_36BITS	(1 << TCR_EL2_PS_SHIFT)
#define	 TCR_EL2_PS_40BITS	(2 << TCR_EL2_PS_SHIFT)
#define	 TCR_EL2_PS_42BITS	(3 << TCR_EL2_PS_SHIFT)
#define	 TCR_EL2_PS_44BITS	(4 << TCR_EL2_PS_SHIFT)
#define	 TCR_EL2_PS_48BITS	(5 << TCR_EL2_PS_SHIFT)
#define	 TCR_EL2_PS_52BITS	(6 << TCR_EL2_PS_SHIFT)	/* ARMv8.2-LPA */

/* VMPDIR_EL2 - Virtualization Multiprocessor ID Register */
#define	VMPIDR_EL2_U		0x0000000040000000
#define	VMPIDR_EL2_MT		0x0000000001000000
#define	VMPIDR_EL2_RES1		0x0000000080000000

/* VTCR_EL2 - Virtualization Translation Control Register */
#define	VTCR_EL2_RES1		(0x1 << 31)
#define	VTCR_EL2_T0SZ_MASK	0x3f
#define	VTCR_EL2_SL0_SHIFT	6
#define	 VTCR_EL2_SL0_4K_LVL2	(0x0 << VTCR_EL2_SL0_SHIFT)
#define	 VTCR_EL2_SL0_4K_LVL1	(0x1 << VTCR_EL2_SL0_SHIFT)
#define	 VTCR_EL2_SL0_4K_LVL0	(0x2 << VTCR_EL2_SL0_SHIFT)
#define	VTCR_EL2_IRGN0_SHIFT	8
#define	 VTCR_EL2_IRGN0_WBWA	(0x1 << VTCR_EL2_IRGN0_SHIFT)
#define	VTCR_EL2_ORGN0_SHIFT	10
#define	 VTCR_EL2_ORGN0_WBWA	(0x1 << VTCR_EL2_ORGN0_SHIFT)
#define	VTCR_EL2_SH0_SHIFT	12
#define	 VTCR_EL2_SH0_NS	(0x0 << VTCR_EL2_SH0_SHIFT)
#define	 VTCR_EL2_SH0_OS	(0x2 << VTCR_EL2_SH0_SHIFT)
#define	 VTCR_EL2_SH0_IS	(0x3 << VTCR_EL2_SH0_SHIFT)
#define	VTCR_EL2_TG0_SHIFT	14
#define	 VTCR_EL2_TG0_4K	(0x0 << VTCR_EL2_TG0_SHIFT)
#define	 VTCR_EL2_TG0_64K	(0x1 << VTCR_EL2_TG0_SHIFT)
#define	 VTCR_EL2_TG0_16K	(0x2 << VTCR_EL2_TG0_SHIFT)
#define	VTCR_EL2_PS_SHIFT	16
#define	 VTCR_EL2_PS_32BIT	(0x0 << VTCR_EL2_PS_SHIFT)
#define	 VTCR_EL2_PS_36BIT	(0x1 << VTCR_EL2_PS_SHIFT)
#define	 VTCR_EL2_PS_40BIT	(0x2 << VTCR_EL2_PS_SHIFT)
#define	 VTCR_EL2_PS_42BIT	(0x3 << VTCR_EL2_PS_SHIFT)
#define	 VTCR_EL2_PS_44BIT	(0x4 << VTCR_EL2_PS_SHIFT)
#define	 VTCR_EL2_PS_48BIT	(0x5 << VTCR_EL2_PS_SHIFT)

/* VTTBR_EL2 - Virtualization Translation Table Base Register */
#define	VTTBR_VMID_MASK		0xffff000000000000
#define	VTTBR_VMID_SHIFT	48
#define	VTTBR_HOST		0x0000000000000000

/* VTCR_EL2 - Virtualization Translation Control Register */
#define	VTCR_EL2_RES1		(0x1 << 31)
#define	VTCR_EL2_T0SZ_MASK	0x3f
#define VTCR_EL2_SL0_SHIFT	6
#define	 VTCR_EL2_SL0_4K_LVL2	(0x0 << VTCR_EL2_SL0_SHIFT)
#define	 VTCR_EL2_SL0_4K_LVL1	(0x1 << VTCR_EL2_SL0_SHIFT)
#define	 VTCR_EL2_SL0_4K_LVL0	(0x2 << VTCR_EL2_SL0_SHIFT)
#define VTCR_EL2_IRGN0_SHIFT	8
#define	 VTCR_EL2_IRGN0_WBWA	(0x1 << VTCR_EL2_IRGN0_SHIFT)
#define VTCR_EL2_ORGN0_SHIFT	10
#define	 VTCR_EL2_ORGN0_WBWA	(0x1 << VTCR_EL2_ORGN0_SHIFT)
#define	VTCR_EL2_SH0_SHIFT	12
#define	 VTCR_EL2_SH0_NS	(0x0 << VTCR_EL2_SH0_SHIFT)
#define	 VTCR_EL2_SH0_OS	(0x2 << VTCR_EL2_SH0_SHIFT)
#define	 VTCR_EL2_SH0_IS	(0x3 << VTCR_EL2_SH0_SHIFT)
#define	VTCR_EL2_TG0_SHIFT	14
#define	 VTCR_EL2_TG0_4K	(0x0 << VTCR_EL2_TG0_SHIFT)
#define	 VTCR_EL2_TG0_64K	(0x1 << VTCR_EL2_TG0_SHIFT)
#define	 VTCR_EL2_TG0_16K	(0x2 << VTCR_EL2_TG0_SHIFT)
#define	VTCR_EL2_PS_SHIFT	16
#define  VTCR_EL2_PS_32BIT	(0x0 << VTCR_EL2_PS_SHIFT)
#define  VTCR_EL2_PS_36BIT	(0x1 << VTCR_EL2_PS_SHIFT)
#define  VTCR_EL2_PS_40BIT	(0x2 << VTCR_EL2_PS_SHIFT)
#define  VTCR_EL2_PS_42BIT	(0x3 << VTCR_EL2_PS_SHIFT)
#define  VTCR_EL2_PS_44BIT	(0x4 << VTCR_EL2_PS_SHIFT)
#define  VTCR_EL2_PS_48BIT	(0x5 << VTCR_EL2_PS_SHIFT)

/* HPFAR_EL2 - Hypervisor IPA Fault Address Register */
#define	HPFAR_EL2_FIPA_SHIFT	4
#define HPFAR_EL2_FIPA_MASK	0xfffffffff0

#endif /* !_MACHINE_HYPERVISOR_H_ */
