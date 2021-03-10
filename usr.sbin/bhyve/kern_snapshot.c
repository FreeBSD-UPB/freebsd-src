#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <machine/atomic.h>
#include <machine/segments.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sysexits.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <machine/vmm.h>
#ifndef WITHOUT_CAPSICUM
#include <machine/vmm_dev.h>
#endif
#include <machine/vmm_snapshot.h>
#include <vmmapi.h>

#ifdef JSON_SNAPSHOT_V2
/* ################## kernel snapshot functions copies ##################### */

/* vhpet */
int
vhpet_snapshot(struct vm_snapshot_meta *meta)
{
	struct vhpet_userspace *vhpet;
	struct timer_userspace *timer;
    int i, ret = 0;

    SNAPSHOT_VAR_OR_LEAVE(vhpet->freq_sbt, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vhpet->config, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vhpet->isr, meta, ret, done);

    SNAPSHOT_VAR_OR_LEAVE(vhpet->countbase, meta, ret, done);

	SNAPSHOT_ADD_INTERN_ARR(timers, meta);
    for (i = 0; i < nitems(vhpet->timer); i++) {
		timer = &vhpet->timer[i];
		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);

        SNAPSHOT_VAR_OR_LEAVE(timer->cap_config, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(timer->msireg, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(timer->compval, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(timer->comprate, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(timer->callout_sbt, meta, ret, done);
    }
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(timers, meta);

done:
    return (ret);
}


/* vioapic */
int
vioapic_snapshot(struct vm_snapshot_meta *meta)
{
	struct rtbl_userspace *rtbl;
	struct vioapic_userspace *vioapic;
    int ret;
    int i;

    SNAPSHOT_VAR_OR_LEAVE(vioapic->ioregsel, meta, ret, done);

	SNAPSHOT_ADD_INTERN_ARR(rtbls, meta);
    for (i = 0; i < nitems(vioapic->rtbl); i++) {
		rtbl = &vioapic->rtbl[i];
		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);

        SNAPSHOT_VAR_OR_LEAVE(rtbl->reg, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(rtbl->acnt, meta, ret, done);
    }
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(rtbls, meta);

done:
    return (ret);
}

/* vm (vcpus) */ 
static int 
vm_snapshot_vcpus(struct vm_userspace *vm, struct vm_snapshot_meta *meta) 
{ 
    int ret; 
    int i; 
    struct vcpu_userspace *vcpu;

	SNAPSHOT_ADD_INTERN_ARR(vcpus, meta);
    for (i = 0; i < VM_MAXCPU; i++) { 
        vcpu = &vm->vcpu[i];
		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);
 
        SNAPSHOT_VAR_OR_LEAVE(vcpu->x2apic_state, meta, ret, done); 
        SNAPSHOT_VAR_OR_LEAVE(vcpu->exitintinfo, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vcpu->exc_vector, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vcpu->exc_errcode_valid, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vcpu->exc_errcode, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vcpu->guest_xcr0, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vcpu->exitinfo, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vcpu->nextrip, meta, ret, done);

        SNAPSHOT_VAR_OR_LEAVE(vcpu->tsc_offset, meta, ret, done);
    }
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(vcpus, meta);

done:
    return (ret);
}

int
vm_snapshot_vm(struct vm_snapshot_meta *meta)
{
    int ret;
	struct vm_userspace *vm;

    ret = 0;

    ret = vm_snapshot_vcpus(vm, meta);
    if (ret != 0) {
        printf("%s: failed to copy vm data to user buffer", __func__);
        goto done;
    }

done:
    return (ret);
}

/* vlapic */
int
vlapic_snapshot(struct vm_snapshot_meta *meta)
{
    int i, ret;
    struct vlapic_userspace *vlapic;
    uint32_t ccr;

    ret = 0;

	SNAPSHOT_ADD_INTERN_ARR(vlapic, meta);
    for (i = 0; i < VM_MAXCPU; i++) {
		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);

        /* snapshot the page first; timer period depends on icr_timer */
        SNAPSHOT_BUF_OR_LEAVE(vlapic->apic_page, PAGE_SIZE, meta, ret, done);

        SNAPSHOT_VAR_OR_LEAVE(vlapic->esr_pending, meta, ret, done);

        SNAPSHOT_VAR_OR_LEAVE(vlapic->timer_freq_bt.sec,
                      meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vlapic->timer_freq_bt.frac,
                      meta, ret, done);

        SNAPSHOT_BUF_OR_LEAVE(vlapic->isrvec_stk,
                      sizeof(vlapic->isrvec_stk),
                      meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vlapic->isrvec_stk_top, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vlapic->boot_state, meta, ret, done);

        SNAPSHOT_BUF_OR_LEAVE(vlapic->lvt_last,
                      sizeof(vlapic->lvt_last),
                      meta, ret, done);

        SNAPSHOT_VAR_OR_LEAVE(ccr, meta, ret, done);
    }
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(vlapic, meta);

done:
    return (ret);
}

/* vatpic */
int
vatpic_snapshot(struct vm_snapshot_meta *meta)
{
    int ret;
    int i;
    struct atpic_userspace *atpic;
	struct vatpic_userspace *vatpic; 

	SNAPSHOT_ADD_INTERN_ARR(atpic, meta);
    for (i = 0; i < nitems(vatpic->atpic); i++) {
        atpic = &vatpic->atpic[i];
		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);

        SNAPSHOT_VAR_OR_LEAVE(atpic->ready, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->icw_num, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->rd_cmd_reg, meta, ret, done);

        SNAPSHOT_VAR_OR_LEAVE(atpic->aeoi, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->poll, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->rotate, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->sfn, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->irq_base, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->request, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->service, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->mask, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->smm, meta, ret, done);

        SNAPSHOT_BUF_OR_LEAVE(atpic->acnt, sizeof(atpic->acnt),
                      meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->lowprio, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(atpic->intr_raised, meta, ret, done);
    }
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(atpic, meta);

    SNAPSHOT_BUF_OR_LEAVE(vatpic->elc, sizeof(vatpic->elc),
                  meta, ret, done);

done:
    return (ret);
}

/* vatpit */
int
vatpit_snapshot(struct vm_snapshot_meta *meta)
{
    int ret;    
    int i;
    struct channel_userspace *channel;
	struct vatpit_userspace *vatpit;

    SNAPSHOT_VAR_OR_LEAVE(vatpit->freq_bt.sec, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vatpit->freq_bt.frac, meta, ret, done);

	SNAPSHOT_ADD_INTERN_ARR(channels, meta);	
    for (i = 0; i < nitems(vatpit->channel); i++) {
        channel = &vatpit->channel[i];
		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);

        SNAPSHOT_VAR_OR_LEAVE(channel->mode, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(channel->initial, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(channel->now_bt.sec, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(channel->now_bt.frac, meta, ret, done);
        SNAPSHOT_BUF_OR_LEAVE(channel->cr, sizeof(channel->cr),
            meta, ret, done);
        SNAPSHOT_BUF_OR_LEAVE(channel->ol, sizeof(channel->ol),
            meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(channel->slatched, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(channel->status, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(channel->crbyte, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(channel->frbyte, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(channel->callout_bt.sec, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(channel->callout_bt.frac, meta, ret,
            done);
    }
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(channels, meta);

done:
    return (ret);
}

/* vmptmr */
int
vpmtmr_snapshot(struct vm_snapshot_meta *meta)
{
    int ret;
	struct vpmtmr_userspace *vpmtmr; 

    SNAPSHOT_VAR_OR_LEAVE(vpmtmr->baseval, meta, ret, done);

done:
    return (ret);
}

/* vrtc */
int
vrtc_snapshot(struct vm_snapshot_meta *meta)
{
    int ret;
	struct vrtc_userspace *vrtc; 

    SNAPSHOT_VAR_OR_LEAVE(vrtc->addr, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->base_rtctime, meta, ret, done);

    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.sec, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.alarm_sec, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.min, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.alarm_min, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.hour, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.alarm_hour, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.day_of_week, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.day_of_month, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.month, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.year, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.reg_a, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.reg_b, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.reg_c, meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.reg_d, meta, ret, done);
    SNAPSHOT_BUF_OR_LEAVE(vrtc->rtcdev.nvram, sizeof(vrtc->rtcdev.nvram),
                  meta, ret, done);
    SNAPSHOT_VAR_OR_LEAVE(vrtc->rtcdev.century, meta, ret, done);
    SNAPSHOT_BUF_OR_LEAVE(vrtc->rtcdev.nvram2, sizeof(vrtc->rtcdev.nvram2),
                  meta, ret, done);

done:
    return (ret);
}

/* vmx */
int
vmx_snapshot(struct vm_snapshot_meta *meta)
{
    struct vmx_userspace *vmx;
    struct vmxctx_userspace *vmxctx;
    int i;
	uint64_t *guest_msrs;
    int ret;

	SNAPSHOT_ADD_INTERN_ARR(vmx, meta);
    for (i = 0; i < VM_MAXCPU; i++) {
		guest_msrs = vmx->guest_msrs[i];
		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);
        SNAPSHOT_BUF_OR_LEAVE(guest_msrs,
              sizeof(vmx->guest_msrs[i]), meta, ret, done);

		SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
		SNAPSHOT_ADD_INTERN_ARR(guest_registers, meta);
        vmxctx = &vmx->ctx[i];
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rdi, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rsi, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rdx, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rcx, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r8, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r9, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rax, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rbx, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rbp, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r10, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r11, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r12, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r13, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r14, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r15, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_cr2, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr0, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr1, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr2, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr3, meta, ret, done);
        SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr6, meta, ret, done);
		SNAPSHOT_REMOVE_INTERN_ARR(guest_registers, meta);
    }
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(vmx, meta);

done:
    return (ret);
}

/* vmcx */
static int
vmcs_snapshot_desc(struct vm_snapshot_meta *meta)
{
    int ret;
    struct seg_desc desc;

	SNAPSHOT_VAR_OR_LEAVE(desc.base, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(desc.limit, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(desc.access, meta, ret, done);

done:
    return (ret);
}

int
vmx_vmcx_snapshot(struct vm_snapshot_meta *meta)
{
    struct vmcs_userspace *vmcs;
    struct vmx_userspace *vmx;
    int err, i;
	uint64_t vm_reg_guest_cr0, vm_reg_guest_cr3, vm_reg_guest_cr4;
	uint64_t vm_reg_guest_dr7, vm_reg_guest_rsp, vm_reg_guest_rip;
	uint64_t vm_reg_guest_rflags;

	uint64_t vm_reg_guest_es, vm_reg_guest_cs, vm_reg_guest_ss, vm_reg_guest_ds;
	uint64_t vm_reg_guest_fs, vm_reg_guest_gs, vm_reg_guest_tr;
	uint64_t vm_reg_guest_ldtr, vm_reg_guest_efer;

	uint64_t vm_reg_guest_pdpte0, vm_reg_guest_pdpte1;
	uint64_t vm_reg_guest_pdpte2, vm_reg_guest_pdpte3;

	uint64_t vmcs_guest_ia32_sysenter_cs, vmcs_guest_ia32_sysenter_esp;
	uint64_t vmcs_guest_ia32_sysenter_eip, vmcs_guest_interruptibility;
	uint64_t vmcs_guest_activity, vmcs_entry_ctls, vmcs_exit_ctls;

	SNAPSHOT_ADD_INTERN_ARR(vcpu, meta);
	for (i = 0; i < VM_MAXCPU; i++) {
		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);
    	err = 0;

    	vmcs = &vmx->vmcs[i];

    	vm_reg_guest_cr0 = VM_REG_GUEST_CR0;
		vm_reg_guest_cr3 = VM_REG_GUEST_CR3;
		vm_reg_guest_cr4 = VM_REG_GUEST_CR4;
		vm_reg_guest_dr7 = VM_REG_GUEST_DR7;
		vm_reg_guest_rsp = VM_REG_GUEST_RSP;
		vm_reg_guest_rip = VM_REG_GUEST_RIP;
		vm_reg_guest_rflags = VM_REG_GUEST_RFLAGS;

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_cr0, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_cr3, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_cr4, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_dr7, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_rsp, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_rip, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_rflags, meta, err, done);

		SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);

    	/* Guest segments */
		SNAPSHOT_ADD_INTERN_ARR(guest_segments, meta);

		vm_reg_guest_es = VM_REG_GUEST_ES;
		vm_reg_guest_cs = VM_REG_GUEST_CS;
		vm_reg_guest_ss = VM_REG_GUEST_SS;
		vm_reg_guest_ds = VM_REG_GUEST_DS;
		vm_reg_guest_fs = VM_REG_GUEST_FS;
		vm_reg_guest_gs = VM_REG_GUEST_GS;
		vm_reg_guest_tr = VM_REG_GUEST_TR;
		vm_reg_guest_ldtr = VM_REG_GUEST_LDTR;
		vm_reg_guest_efer = VM_REG_GUEST_EFER;

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_es, meta, err, done);
		SNAPSHOT_ADD_INTERN_ARR(es_desc, meta);
    	err += vmcs_snapshot_desc(meta);
		SNAPSHOT_REMOVE_INTERN_ARR(es_desc, meta);

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_cs, meta, err, done);
		SNAPSHOT_ADD_INTERN_ARR(cs_desc, meta);
    	err += vmcs_snapshot_desc(meta);
		SNAPSHOT_REMOVE_INTERN_ARR(cs_desc, meta);

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_ss, meta, err, done);
		SNAPSHOT_ADD_INTERN_ARR(ss_desc, meta);
    	err += vmcs_snapshot_desc(meta);
		SNAPSHOT_REMOVE_INTERN_ARR(ss_desc, meta);

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_ds, meta, err, done);
		SNAPSHOT_ADD_INTERN_ARR(ds_desc, meta);
    	err += vmcs_snapshot_desc(meta);
		SNAPSHOT_REMOVE_INTERN_ARR(ds_desc, meta);

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_fs, meta, err, done);
		SNAPSHOT_ADD_INTERN_ARR(fs_desc, meta);
    	err += vmcs_snapshot_desc(meta);
		SNAPSHOT_REMOVE_INTERN_ARR(fs_desc, meta);

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_gs, meta, err, done);
		SNAPSHOT_ADD_INTERN_ARR(gs_desc, meta);
    	err += vmcs_snapshot_desc(meta);
		SNAPSHOT_REMOVE_INTERN_ARR(gs_desc, meta);

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_tr, meta, err, done);
		SNAPSHOT_ADD_INTERN_ARR(tr_desc, meta);
    	err += vmcs_snapshot_desc(meta);
		SNAPSHOT_REMOVE_INTERN_ARR(tr_desc, meta);

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_ldtr, meta, err, done);
		SNAPSHOT_ADD_INTERN_ARR(ldtr_desc, meta);
    	err += vmcs_snapshot_desc(meta);
		SNAPSHOT_REMOVE_INTERN_ARR(ldtr_desc, meta);

		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_efer, meta, err, done);

		SNAPSHOT_ADD_INTERN_ARR(efer_desc, meta);
    	err += vmcs_snapshot_desc(meta);
		SNAPSHOT_REMOVE_INTERN_ARR(efer_desc, meta);

    	err += vmcs_snapshot_desc(meta);

		SNAPSHOT_REMOVE_INTERN_ARR(guest_segments, meta);

    	/* Guest page tables */
		vm_reg_guest_pdpte0 = VM_REG_GUEST_PDPTE0;
		vm_reg_guest_pdpte1 = VM_REG_GUEST_PDPTE1;
		vm_reg_guest_pdpte2 = VM_REG_GUEST_PDPTE2;
		vm_reg_guest_pdpte3 = VM_REG_GUEST_PDPTE3;

		SNAPSHOT_ADD_INTERN_ARR(guest_page_tables, meta);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_pdpte0, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_pdpte1, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_pdpte2, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vm_reg_guest_pdpte3, meta, err, done);
		SNAPSHOT_REMOVE_INTERN_ARR(guest_page_tables, meta);

    	/* Other guest state */
		vmcs_guest_ia32_sysenter_cs = VMCS_GUEST_IA32_SYSENTER_CS;
		vmcs_guest_ia32_sysenter_esp = VMCS_GUEST_IA32_SYSENTER_ESP;
		vmcs_guest_ia32_sysenter_eip = VMCS_GUEST_IA32_SYSENTER_EIP;
		vmcs_guest_interruptibility = VMCS_GUEST_INTERRUPTIBILITY;
		vmcs_guest_activity = VMCS_GUEST_ACTIVITY;
		vmcs_entry_ctls = VMCS_ENTRY_CTLS;
		vmcs_exit_ctls = VMCS_EXIT_CTLS;

		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);
		SNAPSHOT_VAR_OR_LEAVE(vmcs_guest_ia32_sysenter_cs, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vmcs_guest_ia32_sysenter_esp, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vmcs_guest_ia32_sysenter_eip, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vmcs_guest_interruptibility, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vmcs_guest_activity, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vmcs_entry_ctls, meta, err, done);
		SNAPSHOT_VAR_OR_LEAVE(vmcs_exit_ctls, meta, err, done);
	}
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(vcpu, meta);

done:
    return (err);
}

/* ################## kernel snapshot functions copies ##################### */

#endif

