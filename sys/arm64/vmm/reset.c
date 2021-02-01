/*
 * Copyright (C) 2015-2021 Mihai Carabas <mihai.carabas@gmail.com>
 * Copyright (C) 2017-2019 Alexandru Elisei <alexandru.elisei@gmail.com>
 * Copyright (C) 2017-2021 Darius Mihai <darius.mihai.m@gmail.com>
 * Copyright (C) 2019-2021 Andrei Martin <andrei.cos.martin@gmail.com>
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>

#include <machine/armreg.h>
#include <machine/cpu.h>
#include <machine/hypervisor.h>

#include "arm64.h"
#include "reset.h"

/*
 * Make the architecturally UNKNOWN value 0. As a bonus, we don't have to
 * manually set all those RES0 fields.
 */
#define	ARCH_UNKNOWN		0
#define	set_arch_unknown(reg)	(memset(&(reg), ARCH_UNKNOWN, sizeof(reg)))

void
reset_vm_el01_regs(void *vcpu)
{
	struct hypctx *el2ctx;

	el2ctx = vcpu;

	set_arch_unknown(el2ctx->regs);

	set_arch_unknown(el2ctx->actlr_el1);
	set_arch_unknown(el2ctx->afsr0_el1);
	set_arch_unknown(el2ctx->afsr1_el1);
	set_arch_unknown(el2ctx->amair_el1);
	set_arch_unknown(el2ctx->contextidr_el1);
	set_arch_unknown(el2ctx->cpacr_el1);
	set_arch_unknown(el2ctx->elr_el1);
	set_arch_unknown(el2ctx->esr_el1);
	set_arch_unknown(el2ctx->far_el1);
	set_arch_unknown(el2ctx->mair_el1);
	set_arch_unknown(el2ctx->par_el1);

	/*
	 * Guest starts with:
	 * ~SCTLR_M: MMU off
	 * ~SCTLR_C: data cache off
	 * SCTLR_CP15BEN: memory barrier instruction enable from EL0; RAO/WI
	 * ~SCTLR_I: instruction cache off
	 */
	el2ctx->sctlr_el1 = SCTLR_RES1;
	el2ctx->sctlr_el1 &= ~SCTLR_M & ~SCTLR_C & ~SCTLR_I;
	el2ctx->sctlr_el1 |= SCTLR_CP15BEN;

	set_arch_unknown(el2ctx->sp_el0);
	set_arch_unknown(el2ctx->tcr_el1);
	set_arch_unknown(el2ctx->tpidr_el0);
	set_arch_unknown(el2ctx->tpidr_el1);
	set_arch_unknown(el2ctx->tpidrro_el0);
	set_arch_unknown(el2ctx->ttbr0_el1);
	set_arch_unknown(el2ctx->ttbr1_el1);
	set_arch_unknown(el2ctx->vbar_el1);
	set_arch_unknown(el2ctx->spsr_el1);
}

void
reset_vm_el2_regs(void *vcpu)
{
	struct hypctx *el2ctx;
	uint64_t cpu_aff;

	el2ctx = vcpu;

	/*
	 * Set the Hypervisor Configuration Register:
	 *
	 * HCR_RW: use AArch64 for EL1
	 * HCR_BSU_IS: barrier instructions apply to the inner shareable
	 * domain
	 * HCR_SWIO: turn set/way invalidate into set/way clean and
	 * invalidate
	 * HCR_FB: broadcast maintenance operations
	 * HCR_AMO: route physical SError interrupts to EL2
	 * HCR_IMO: route physical IRQ interrupts to EL2
	 * HCR_FMO: route physical FIQ interrupts to EL2
	 * HCR_VM: use stage 2 translation
	 */
	el2ctx->hcr_el2 = HCR_RW | HCR_BSU_IS | HCR_SWIO | HCR_FB | \
			  HCR_VM | HCR_AMO | HCR_IMO | HCR_FMO;

	el2ctx->vmpidr_el2 = VMPIDR_EL2_RES1;
	/* The guest will detect a multi-core, single-threaded CPU */
	el2ctx->vmpidr_el2 &= ~VMPIDR_EL2_U & ~VMPIDR_EL2_MT;
	/* Only 24 bits of affinity, for a grand total of 16,777,216 cores. */
	cpu_aff = el2ctx->vcpu & (CPU_AFF0_MASK | CPU_AFF1_MASK | CPU_AFF2_MASK);
	el2ctx->vmpidr_el2 |= cpu_aff;

	/* Use the same CPU identification information as the host */
	el2ctx->vpidr_el2 = CPU_IMPL_TO_MIDR(CPU_IMPL_ARM);
	el2ctx->vpidr_el2 |= CPU_VAR_TO_MIDR(0);
	el2ctx->vpidr_el2 |= CPU_ARCH_TO_MIDR(0xf);
	el2ctx->vpidr_el2 |= CPU_PART_TO_MIDR(CPU_PART_FOUNDATION);
	el2ctx->vpidr_el2 |= CPU_REV_TO_MIDR(0);

	/*
	 * Don't trap accesses to CPACR_EL1, trace, SVE, Advanced SIMD
	 * and floating point functionality to EL2.
	 */
	el2ctx->cptr_el2 = CPTR_RES1;
	/*
	 * Disable interrupts in the guest. The guest OS will re-enable
	 * them.
	 */
	el2ctx->spsr_el2 = PSR_D | PSR_A | PSR_I | PSR_F;
	/* Use the EL1 stack when taking exceptions to EL1 */
	el2ctx->spsr_el2 |= PSR_M_EL1h;
}
