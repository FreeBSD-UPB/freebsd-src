/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2016 Flavius Anton
 * Copyright (c) 2016 Mihai Tiganus
 * Copyright (c) 2016-2019 Mihai Carabas
 * Copyright (c) 2017-2019 Darius Mihai
 * Copyright (c) 2017-2019 Elena Mihailescu
 * Copyright (c) 2018-2019 Sergiu Weisz
 * All rights reserved.
 * The bhyve-snapshot feature was developed under sponsorships
 * from Matthew Grooms.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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

#include "bhyverun.h"
#include "acpi.h"
#include "atkbdc.h"
#include "debug.h"
#include "inout.h"
//#include "dbgport.h"
#include "fwctl.h"
#include "ioapic.h"
#include "mem.h"
#include "mevent.h"
#include "mptbl.h"
#include "pci_emul.h"
#include "pci_irq.h"
#include "pci_lpc.h"
#include "smbiostbl.h"
#include "snapshot.h"
#include "xmsr.h"
#include "spinup_ap.h"
#include "rtc.h"

#include <libxo/xo.h>
#include <ucl.h>

#ifdef JSON_SNAPSHOT_V2

#include <openssl/evp.h>
//#include <search.h>

#include "../lib/libc/stdlib/hsearch.h"

#endif

struct spinner_info {
	const size_t *crtval;
	const size_t maxval;
	const size_t total;
};

extern int guest_ncpus;

static struct winsize winsize;
static sig_t old_winch_handler;

#ifdef JSON_SNAPSHOT_V2

struct type_info {
	char type_name[24];
	char fmt_str[24];
	unsigned char size;
};

static struct hsearch_data *types_htable;





/* TODO - Move these somewhere else */
#define VHPET_NUM_TIMERS    8

struct timer {
        uint64_t    cap_config; /* Configuration */
        uint64_t    msireg;     /* FSB interrupt routing */
        uint32_t    compval;    /* Comparator */
        uint32_t    comprate;
        // struct callout  callout;
        sbintime_t  callout_sbt;    /* time when counter==compval */
        // struct vhpet_callout_arg arg;
};

struct vhpet {
    // struct vm   *vm;
    // struct mtx  mtx;
    sbintime_t  freq_sbt;

    uint64_t    config;     /* Configuration */
    uint64_t    isr;        /* Interrupt Status */
    uint32_t    countbase;  /* HPET counter base value */
    sbintime_t  countbase_sbt;  /* uptime corresponding to base value */

    struct timer timer[VHPET_NUM_TIMERS];
};

static int
vhpet_snapshot(struct vm_snapshot_meta *meta)
{
	struct vhpet *vhpet;
	struct timer *timer;
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

#define REDIR_ENTRIES   32

struct rtbl {
	uint64_t reg;
	int acnt;	/* sum of pin asserts (+1) and deasserts (-1) */
};

struct vioapic {
    // struct vm   *vm;
    // struct mtx  mtx;
    uint32_t    id;
    uint32_t    ioregsel;
    struct rtbl rtbl[REDIR_ENTRIES];
};

int
vioapic_snapshot(struct vm_snapshot_meta *meta)
{
	struct rtbl *rtbl;
	struct vioapic *vioapic;
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
/*
 * Initialization:
 * (a) allocated when vcpu is created
 * (i) initialized when vcpu is created and when it is reinitialized
 * (o) initialized the first time the vcpu is created
 * (x) initialized before use
 */
struct vcpu {
    // struct mtx  mtx;        /* (o) protects 'state' and 'hostcpu' */
    // enum vcpu_state state;      /* (o) vcpu state */
    // int     hostcpu;    /* (o) vcpu's host cpu */
    // int     reqidle;    /* (i) request vcpu to idle */
    // struct vlapic   *vlapic;    /* (i) APIC device model */
    enum x2apic_state x2apic_state; /* (i) APIC mode */
    uint64_t    exitintinfo;    /* (i) events pending at VM exit */
    // int     nmi_pending;    /* (i) NMI pending */
    // int     extint_pending; /* (i) INTR pending */
    // int exception_pending;  /* (i) exception pending */
    int exc_vector;     /* (x) exception collateral */
    int exc_errcode_valid;
    uint32_t exc_errcode;
    // struct savefpu  *guestfpu;  /* (a,i) guest fpu state */
    uint64_t    guest_xcr0; /* (i) guest %xcr0 register */
    // void        *stats;     /* (a,i) statistics */
    struct vm_exit  exitinfo;   /* (x) exit reason and collateral */
    uint64_t    nextrip;    /* (x) next instruction to execute */
    uint64_t    tsc_offset; /* (o) TSC offsetting */
};

/*
 * Initialization:
 * (o) initialized the first time the VM is created
 * (i) initialized when VM is created and when it is reinitialized
 * (x) initialized before use
 */
struct vm {
    // void        *cookie;        /* (i) cpu-specific data */
    // void        *iommu;         /* (x) iommu-specific data */
    // struct vhpet    *vhpet;         /* (i) virtual HPET */
    // struct vioapic  *vioapic;       /* (i) virtual ioapic */
    // struct vatpic   *vatpic;        /* (i) virtual atpic */
    // struct vatpit   *vatpit;        /* (i) virtual atpit */
    // struct vpmtmr   *vpmtmr;        /* (i) virtual ACPI PM timer */
    // struct vrtc *vrtc;          /* (o) virtual RTC */
    // volatile cpuset_t active_cpus;      /* (i) active vcpus */
    // volatile cpuset_t debug_cpus;       /* (i) vcpus stopped for debug */
    // int     suspend;        /* (i) stop VM execution */
    // volatile cpuset_t suspended_cpus;   /* (i) suspended vcpus */
    // volatile cpuset_t halted_cpus;      /* (x) cpus in a hard halt */
    // cpuset_t    rendezvous_req_cpus;    /* (x) rendezvous requested */
    // cpuset_t    rendezvous_done_cpus;   /* (x) rendezvous finished */
    // void        *rendezvous_arg;    /* (x) rendezvous func/arg */
    // vm_rendezvous_func_t rendezvous_func;
    // struct mtx  rendezvous_mtx;     /* (o) rendezvous lock */
    // struct mem_map  mem_maps[VM_MAX_MEMMAPS]; /* (i) guest address space */
    // struct mem_seg  mem_segs[VM_MAX_MEMSEGS]; /* (o) guest memory regions */
    // struct vmspace  *vmspace;       /* (o) guest's address space */
    // char        name[VM_MAX_NAMELEN];   /* (o) virtual machine name */
    struct vcpu vcpu[VM_MAXCPU];    /* (i) guest vcpus */
    /* The following describe the vm cpu topology */
    // uint16_t    sockets;        /* (o) num of sockets */
    // uint16_t    cores;          /* (o) num of cores/socket */
    // uint16_t    threads;        /* (o) num of threads/core */
    // uint16_t    maxcpus;        /* (o) max pluggable cpus */
};

static int 
vm_snapshot_vcpus(struct vm *vm, struct vm_snapshot_meta *meta) 
{ 
    int ret; 
    int i; 
    struct vcpu *vcpu; 

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
        /* XXX we're cheating here, since the value of tsc_offset as
         * saved here is actually the value of the guest's TSC value.
         *
         * It will be turned turned back into an actual offset when the
         * TSC restore function is called
         */
        SNAPSHOT_VAR_OR_LEAVE(vcpu->tsc_offset, meta, ret, done);
    }
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(vcpus, meta);

done:
    return (ret);
}

static int
vm_snapshot_vm(struct vm_snapshot_meta *meta)
{
    int ret;
	struct vm *vm;

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
#define APIC_LVT_CMCI       6
#define APIC_LVT_MAX        APIC_LVT_CMCI

enum boot_state {
    BS_INIT,
    BS_SIPI,
    BS_RUNNING
};

/*
 * 16 priority levels with at most one vector injected per level.
 */
#define ISRVEC_STK_SIZE     (16 + 1)

#define VLAPIC_MAXLVT_INDEX APIC_LVT_CMCI

struct vlapic {
    struct vm       *vm;
    int         vcpuid;
    struct LAPIC        *apic_page;
    // struct vlapic_ops   ops;

    uint32_t        esr_pending;

    // struct callout  callout;    /* vlapic timer */
    struct bintime  timer_fire_bt;  /* callout expiry time */
    struct bintime  timer_freq_bt;  /* timer frequency */
    struct bintime  timer_period_bt; /* timer period */
    // struct mtx  timer_mtx;

    /*
     * The 'isrvec_stk' is a stack of vectors injected by the local apic.
     * A vector is popped from the stack when the processor does an EOI.
     * The vector on the top of the stack is used to compute the
     * Processor Priority in conjunction with the TPR.
     */ 
    uint8_t     isrvec_stk[ISRVEC_STK_SIZE];
    int     isrvec_stk_top;

    uint64_t    msr_apicbase;
    enum boot_state boot_state;

    /*
     * Copies of some registers in the virtual APIC page. We do this for
     * a couple of different reasons:
     * - to be able to detect what changed (e.g. svr_last)
     * - to maintain a coherent snapshot of the register (e.g. lvt_last)
     */
    uint32_t    svr_last;
    uint32_t    lvt_last[VLAPIC_MAXLVT_INDEX + 1];
};

int
vlapic_snapshot(struct vm_snapshot_meta *meta)
{
    int i, ret;
    struct vlapic *vlapic;
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
enum irqstate {
    IRQSTATE_ASSERT,
    IRQSTATE_DEASSERT,
    IRQSTATE_PULSE
};

struct atpic {
    bool        ready;
    int     icw_num;
    int     rd_cmd_reg;

    bool        aeoi;
    bool        poll;
    bool        rotate;
    bool        sfn;        /* special fully-nested mode */

    int     irq_base;
    uint8_t     request;    /* Interrupt Request Register (IIR) */
    uint8_t     service;    /* Interrupt Service (ISR) */
    uint8_t     mask;       /* Interrupt Mask Register (IMR) */
    uint8_t     smm;        /* special mask mode */

    int     acnt[8];    /* sum of pin asserts and deasserts */
    int     lowprio;    /* lowest priority irq */

    bool        intr_raised;
};

struct vatpic {
    // struct vm   *vm;
    // struct mtx  mtx;
    struct atpic    atpic[2];
    uint8_t     elc[2];
};

int
vatpic_snapshot(struct vm_snapshot_meta *meta)
{
    int ret;
    int i;
	uint8_t e;
    struct atpic *atpic;
	struct vatpic *vatpic; 

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

    //SNAPSHOT_BUF_OR_LEAVE(vatpic->elc, sizeof(vatpic->elc),
    //              meta, ret, done);
	SNAPSHOT_ADD_INTERN_ARR(elc, meta);
	for (i = 0; i < nitems(vatpic->elc); i++) {
		e = vatpic->elc[i];
		SNAPSHOT_SET_INTERN_ARR_INDEX(meta, i);

		SNAPSHOT_VAR_OR_LEAVE(e, meta, ret, done);
	}
	SNAPSHOT_CLEAR_INTERN_ARR_INDEX(meta);
	SNAPSHOT_REMOVE_INTERN_ARR(elc, meta);

done:
    return (ret);
}

/* vatpit */
struct vatpit_callout_arg {
    struct vatpit   *vatpit;
    int     channel_num;
};

struct channel {
    int     mode;
    uint16_t    initial;    /* initial counter value */
    struct bintime  now_bt;     /* uptime when counter was loaded */
    uint8_t     cr[2];
    uint8_t     ol[2];
    bool        slatched;   /* status latched */
    uint8_t     status;
    int     crbyte;
    int     olbyte;
    int     frbyte;
    // struct callout  callout;
    struct bintime  callout_bt; /* target time */
    struct vatpit_callout_arg callout_arg;
};

struct vatpit {
    // struct vm   *vm;
    // struct mtx  mtx;

    struct bintime  freq_bt;

    struct channel  channel[3];
};

int
vatpit_snapshot(struct vm_snapshot_meta *meta)
{
    int ret;    
    int i;
    struct channel *channel;
	struct vatpit *vatpit;

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
struct vpmtmr {
    sbintime_t  freq_sbt;
    sbintime_t  baseuptime;
    uint32_t    baseval;
};

int
vpmtmr_snapshot(struct vm_snapshot_meta *meta)
{
    int ret;
	struct vpmtmr *vpmtmr; 

    SNAPSHOT_VAR_OR_LEAVE(vpmtmr->baseval, meta, ret, done);

done:
    return (ret);
}

/* vrtc */

/* Register layout of the RTC */
struct rtcdev {
    uint8_t sec;
    uint8_t alarm_sec;
    uint8_t min;
    uint8_t alarm_min;
    uint8_t hour;
    uint8_t alarm_hour;
    uint8_t day_of_week;
    uint8_t day_of_month;
    uint8_t month;
    uint8_t year;
    uint8_t reg_a;
    uint8_t reg_b;
    uint8_t reg_c;
    uint8_t reg_d;
    uint8_t nvram[36];
    uint8_t century;
    uint8_t nvram2[128 - 51];
} __packed;

struct vrtc {
    // struct vm   *vm;
    // struct mtx  mtx;
    // struct callout  callout;
    u_int       addr;       /* RTC register to read or write */
    sbintime_t  base_uptime;
    time_t      base_rtctime;
    struct rtcdev   rtcdev;
};

int
vrtc_snapshot(struct vm_snapshot_meta *meta)
{
    int ret;
	struct vrtc *vrtc; 

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


#endif

#define	KB		(1024UL)
#define	MB		(1024UL * KB)
#define	GB		(1024UL * MB)

#define	SNAPSHOT_CHUNK	(4 * MB)
#define	PROG_BUF_SZ	(8192)

#define	MAX_VMNAME 100

#define	SNAPSHOT_BUFFER_SIZE (20 * MB)

#define	JSON_STRUCT_ARR_KEY		"structs"
#define	JSON_DEV_ARR_KEY		"devices"
#define	JSON_BASIC_METADATA_KEY 	"basic metadata"
#define	JSON_SNAPSHOT_REQ_KEY		"snapshot_req"
#define	JSON_SIZE_KEY			"size"
#define	JSON_FILE_OFFSET_KEY		"file_offset"

#define	JSON_NCPUS_KEY			"ncpus"
#define	JSON_VMNAME_KEY 		"vmname"
#define	JSON_MEMSIZE_KEY		"memsize"
#define	JSON_MEMFLAGS_KEY		"memflags"

#define JSON_VERSION_KEY		"version"
#define JSON_PARAMS_KEY		"device_params"
#define JSON_PARAM_KEY		"param_name"
#define JSON_PARAM_DATA_KEY		"param_data"
#define JSON_PARAM_DATA_SIZE_KEY	"data_size"
#define JSON_V1		1
#define JSON_V2		2

#define min(a,b)		\
({				\
 __typeof__ (a) _a = (a);	\
 __typeof__ (b) _b = (b); 	\
 _a < _b ? _a : _b;       	\
 })

const struct vm_snapshot_dev_info snapshot_devs[] = {
	{ "atkbdc",	atkbdc_snapshot,	NULL,		NULL		},
	{ "virtio-net",	pci_snapshot,		pci_pause,	pci_resume	},
	{ "virtio-blk",	pci_snapshot,		pci_pause,	pci_resume	},
	{ "lpc",	pci_snapshot,		NULL,		NULL		},
	{ "fbuf",	pci_snapshot,		NULL,		NULL		},
	{ "xhci",	pci_snapshot,		NULL,		NULL		},
	{ "e1000",	pci_snapshot,		NULL,		NULL		},
	{ "ahci",	pci_snapshot,		pci_pause,	pci_resume	},
	{ "ahci-hd",	pci_snapshot,		pci_pause,	pci_resume	},
	{ "ahci-cd",	pci_snapshot,		NULL,		NULL		},
};

const struct vm_snapshot_kern_info snapshot_kern_structs[] = {
	{ "vhpet",	STRUCT_VHPET	},
	{ "vm",		STRUCT_VM	},
	{ "vmx",	STRUCT_VMX	},
	{ "vioapic",	STRUCT_VIOAPIC	},
	{ "vlapic",	STRUCT_VLAPIC	},
	{ "vmcx",	STRUCT_VMCX	},
	{ "vatpit",	STRUCT_VATPIT	},
	{ "vatpic",	STRUCT_VATPIC	},
	{ "vpmtmr",	STRUCT_VPMTMR	},
	{ "vrtc",	STRUCT_VRTC	},
};

static cpuset_t vcpus_active, vcpus_suspended;
static pthread_mutex_t vcpu_lock;
static pthread_cond_t vcpus_idle, vcpus_can_run;
static bool checkpoint_active;

static int
vm_snapshot_dev_intern_arr(xo_handle_t *xop, int ident, int index,
				struct vm_snapshot_device_info **curr_el);

static int
emit_data(xo_handle_t *xop, struct vm_snapshot_device_info *elem);

static int
create_types_hashtable();

void
add_device_info(struct vm_snapshot_device_info *field_info, char *field_name,
				const char *arr_name, int index, volatile void *data,
				char *type, size_t data_size)
{
	size_t field_len, arr_name_len, type_len;

	if (arr_name != NULL) {
		arr_name_len = strlen(arr_name);
		field_info->intern_arr_name = calloc(arr_name_len + 1, sizeof(char));
		assert(field_info->intern_arr_name);
		memcpy(field_info->intern_arr_name, arr_name, arr_name_len);
	} else
		field_info->intern_arr_name = NULL;

	field_len = strlen(field_name);
	field_info->field_name = calloc(field_len + 1, sizeof(char));
	assert(field_info->field_name != NULL);
	memcpy(field_info->field_name, field_name, field_len);

	field_info->index = index;

	if (data_size != 0 && data != NULL) {
		field_info->field_data = calloc(data_size + 1, sizeof(char));
		assert(field_info->field_data != NULL);
		memcpy(field_info->field_data, (uint8_t *)data, data_size);
		field_info->data_size = data_size;
	}

	if (type != NULL) {
		type_len = strlen(type);
		field_info->type = calloc(type_len + 1, sizeof(char));
		assert(field_info->type != NULL);
		memcpy(field_info->type, type, type_len);
	}
}

void
alloc_device_info_elem(struct list_device_info *list, char *field_name,
						volatile void *data, char *type, size_t data_size)
{
	const char *arr_name = NULL;
	struct vm_snapshot_device_info *aux;
	int index;

	aux = calloc(1, sizeof(struct vm_snapshot_device_info));
	assert(aux != NULL);
	aux->ident = list->ident;
	aux->create_instance = list->create_instance;
	if (aux->ident > 0)
		arr_name = list->intern_arr_names[aux->ident - 1];
	if (list->auto_index != -1)
		index = list->auto_index;
	else
		index = list->index;
	add_device_info(aux, field_name, arr_name, index, data, type, data_size);

	if (list->first == NULL) {
		list->first = aux;
		list->last = list->first;
	} else if (list->first == list->last) {
		list->first->next_field = aux;
		list->last = aux;
	} else {
		list->last->next_field = aux;
		list->last = list->last->next_field;
	}
}

void
remove_first_elem(struct list_device_info *list)
{
	struct vm_snapshot_device_info *aux;

	aux = list->first;
	list->first = aux->next_field;
	free(aux);
}

void
free_device_info_list(struct list_device_info *list)
{
	struct vm_snapshot_device_info *curr_el, *aux;

	curr_el = list->first;
	while (curr_el != NULL) {
		free(curr_el->intern_arr_name);
		free(curr_el->field_name);
		free(curr_el->field_data);

		aux = curr_el->next_field;
		free(curr_el);
		curr_el = aux;
	}
	list->ident = 0;
	memset(list->intern_arr_names, 0, IDENT_LEVEL * sizeof(char *));
	list->first = NULL;
	list->last = NULL;
}

/*
 * TODO: Harden this function and all of its callers since 'base_str' is a user
 * provided string.
 */
static char *
strcat_extension(const char *base_str, const char *ext)
{
	char *res;
	size_t base_len, ext_len;

	base_len = strnlen(base_str, MAX_VMNAME);
	ext_len = strnlen(ext, MAX_VMNAME);

	if (base_len + ext_len > MAX_VMNAME) {
		fprintf(stderr, "Filename exceeds maximum length.\n");
		return (NULL);
	}

	res = malloc(base_len + ext_len + 1);
	if (res == NULL) {
		perror("Failed to allocate memory.");
		return (NULL);
	}

	memcpy(res, base_str, base_len);
	memcpy(res + base_len, ext, ext_len);
	res[base_len + ext_len] = 0;

	return (res);
}

void
destroy_restore_state(struct restore_state *rstate)
{
	if (rstate == NULL) {
		fprintf(stderr, "Attempting to destroy NULL restore struct.\n");
		return;
	}

	if (rstate->kdata_map != MAP_FAILED)
		munmap(rstate->kdata_map, rstate->kdata_len);

	if (rstate->kdata_fd > 0)
		close(rstate->kdata_fd);
	if (rstate->vmmem_fd > 0)
		close(rstate->vmmem_fd);

	if (rstate->meta_root_obj != NULL)
		ucl_object_unref(rstate->meta_root_obj);
	if (rstate->meta_parser != NULL)
		ucl_parser_free(rstate->meta_parser);
}

static int
load_vmmem_file(const char *filename, struct restore_state *rstate)
{
	struct stat sb;
	int err;

	rstate->vmmem_fd = open(filename, O_RDONLY);
	if (rstate->vmmem_fd < 0) {
		perror("Failed to open restore file");
		return (-1);
	}

	err = fstat(rstate->vmmem_fd, &sb);
	if (err < 0) {
		perror("Failed to stat restore file");
		goto err_load_vmmem;
	}

	if (sb.st_size == 0) {
		fprintf(stderr, "Restore file is empty.\n");
		goto err_load_vmmem;
	}

	rstate->vmmem_len = sb.st_size;

	return (0);

err_load_vmmem:
	if (rstate->vmmem_fd > 0)
		close(rstate->vmmem_fd);
	return (-1);
}

static int
load_kdata_file(const char *filename, struct restore_state *rstate)
{
	struct stat sb;
	int err;

	rstate->kdata_fd = open(filename, O_RDONLY);
	if (rstate->kdata_fd < 0) {
		perror("Failed to open kernel data file");
		return (-1);
	}

	err = fstat(rstate->kdata_fd, &sb);
	if (err < 0) {
		perror("Failed to stat kernel data file");
		goto err_load_kdata;
	}

	if (sb.st_size == 0) {
		fprintf(stderr, "Kernel data file is empty.\n");
		goto err_load_kdata;
	}

	rstate->kdata_len = sb.st_size;
	rstate->kdata_map = mmap(NULL, rstate->kdata_len, PROT_READ,
				 MAP_SHARED, rstate->kdata_fd, 0);
	if (rstate->kdata_map == MAP_FAILED) {
		perror("Failed to map restore file");
		goto err_load_kdata;
	}

	return (0);

err_load_kdata:
	if (rstate->kdata_fd > 0)
		close(rstate->kdata_fd);
	return (-1);
}

static int
load_metadata_file(const char *filename, struct restore_state *rstate)
{
	const ucl_object_t *obj;
	struct ucl_parser *parser;
	int err;

	parser = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (parser == NULL) {
		fprintf(stderr, "Failed to initialize UCL parser.\n");
		goto err_load_metadata;
	}

	err = ucl_parser_add_file(parser, filename);
	if (err == 0) {
		fprintf(stderr, "Failed to parse metadata file: '%s'\n",
			filename);
		err = -1;
		goto err_load_metadata;
	}

	obj = ucl_parser_get_object(parser);
	if (obj == NULL) {
		fprintf(stderr, "Failed to parse object.\n");
		err = -1;
		goto err_load_metadata;
	}

	rstate->meta_parser = parser;
	rstate->meta_root_obj = (ucl_object_t *)obj;

	return (0);

err_load_metadata:
	if (parser != NULL)
		ucl_parser_free(parser);
	return (err);
}

int
load_restore_file(const char *filename, struct restore_state *rstate)
{
	int err = 0;
	char *kdata_filename = NULL, *meta_filename = NULL;

	assert(filename != NULL);
	assert(rstate != NULL);

	memset(rstate, 0, sizeof(*rstate));
	rstate->kdata_map = MAP_FAILED;

	err = load_vmmem_file(filename, rstate);
	if (err != 0) {
		fprintf(stderr, "Failed to load guest RAM file.\n");
		goto err_restore;
	}

	kdata_filename = strcat_extension(filename, ".kern");
	if (kdata_filename == NULL) {
		fprintf(stderr, "Failed to construct kernel data filename.\n");
		goto err_restore;
	}

	/* TODO - Do not forget to redo the kernel part after testing the userspace part */
	
	err = load_kdata_file(kdata_filename, rstate);
	if (err != 0) {
		fprintf(stderr, "Failed to load guest kernel data file.\n");
		goto err_restore;
	}
	

	meta_filename = strcat_extension(filename, ".meta");
	if (meta_filename == NULL) {
		fprintf(stderr, "Failed to construct kernel metadata filename.\n");
		goto err_restore;
	}

	err = load_metadata_file(meta_filename, rstate);
	if (err != 0) {
		fprintf(stderr, "Failed to load guest metadata file.\n");
		goto err_restore;
	}

	return (0);

err_restore:
	destroy_restore_state(rstate);
	if (kdata_filename != NULL)
		free(kdata_filename);
	if (meta_filename != NULL)
		free(meta_filename);
	return (-1);
}

#define JSON_GET_INT_OR_RETURN(key, obj, result_ptr, ret)			\
do {										\
	const ucl_object_t *obj__;						\
	obj__ = ucl_object_lookup(obj, key);					\
	if (obj__ == NULL) {							\
		fprintf(stderr, "Missing key: '%s'", key);			\
		return (ret);							\
	}									\
	if (!ucl_object_toint_safe(obj__, result_ptr)) {			\
		fprintf(stderr, "Cannot convert '%s' value to int.", key);	\
		return (ret);							\
	}									\
} while(0)

#define JSON_GET_STRING_OR_RETURN(key, obj, result_ptr, ret)			\
do {										\
	const ucl_object_t *obj__;						\
	obj__ = ucl_object_lookup(obj, key);					\
	if (obj__ == NULL) {							\
		fprintf(stderr, "Missing key: '%s'", key);			\
		return (ret);							\
	}									\
	if (!ucl_object_tostring_safe(obj__, result_ptr)) {			\
		fprintf(stderr, "Cannot convert '%s' value to string.", key);	\
		return (ret);							\
	}									\
} while(0)

#define JSON_GET_STRING_VALUE_OR_RETURN(key, obj, result_ptr, ret)			\
do {										\
	const ucl_object_t *obj__;						\
	obj__ = ucl_object_lookup(obj, (key));					\
	if (obj__ == NULL) {							\
		fprintf(stderr, "Missing key: '%s'", (key));			\
		return (ret);							\
	}									\
	if (!ucl_object_tostring_safe(obj__, result_ptr)) {			\
		fprintf(stderr, "Cannot convert '%s' value to string.", (key));	\
		return (ret);							\
	}									\
} while(0)

static void *
lookup_struct(enum snapshot_req struct_id, struct restore_state *rstate,
	      size_t *struct_size)
{
	const ucl_object_t *structs = NULL, *obj = NULL;
	ucl_object_iter_t it = NULL;
	int64_t snapshot_req, size, file_offset;

	structs = ucl_object_lookup(rstate->meta_root_obj, JSON_STRUCT_ARR_KEY);
	if (structs == NULL) {
		fprintf(stderr, "Failed to find '%s' object.\n",
			JSON_STRUCT_ARR_KEY);
		return (NULL);
	}

	if (ucl_object_type((ucl_object_t *)structs) != UCL_ARRAY) {
		fprintf(stderr, "Object '%s' is not an array.\n",
		JSON_STRUCT_ARR_KEY);
		return (NULL);
	}

	while ((obj = ucl_object_iterate(structs, &it, true)) != NULL) {
		snapshot_req = -1;
		JSON_GET_INT_OR_RETURN(JSON_SNAPSHOT_REQ_KEY, obj,
				       &snapshot_req, NULL);
		assert(snapshot_req >= 0);
		if ((enum snapshot_req) snapshot_req == struct_id) {
			JSON_GET_INT_OR_RETURN(JSON_SIZE_KEY, obj,
					       &size, NULL);
			assert(size >= 0);

			JSON_GET_INT_OR_RETURN(JSON_FILE_OFFSET_KEY, obj,
					       &file_offset, NULL);
			assert(file_offset >= 0);
			assert(file_offset + size <= rstate->kdata_len);

			*struct_size = (size_t)size;
			return (rstate->kdata_map + file_offset);
		}
	}

	return (NULL);
}

#ifdef JSON_SNAPSHOT_V2

int
extract_type(char **type, const ucl_object_t *obj)
{
	char *key_copy = NULL;
	char *aux = NULL;
	const char delim[2] = "$";

	key_copy = strdup(obj->key);
	assert(key_copy != NULL);

	/* Param name */
    strtok(key_copy, delim);

	aux = strtok(NULL, delim);
	assert(aux != NULL);

	*type = strdup(aux);
	assert(*type != NULL);

	free(key_copy);

	return (0);
}

int
restore_data(const ucl_object_t *obj, struct list_device_info *list)
{
	int ret;
	const char *enc_data;
	char *dec_data;
	int enc_bytes;
	int dec_bytes;
	int64_t data_size;
	int64_t int_data;
	char *type;

	ret = 0;

	extract_type(&type, obj);
	if (!strcmp(type, "int8") ||
		!strcmp(type, "uint8") ||
		!strcmp(type, "int16") ||
		!strcmp(type, "uint16") ||
		!strcmp(type, "int32") ||
		!strcmp(type, "uint32") ||
		!strcmp(type, "int64") ||
		!strcmp(type, "uint64")) {

		int_data = 0;
		if (!ucl_object_toint_safe(obj, &int_data)) {
			fprintf(stderr, "Cannot convert '%s' value to int_t.", obj->key);
			ret = -1;
			goto done;
		}

		alloc_device_info_elem(list, (char *)obj->key, &int_data, NULL, sizeof(int_data));
	} else {
		enc_data = NULL;
		if (!ucl_object_tostring_safe(obj, &enc_data)) {
			fprintf(stderr, "Cannot convert '%s' value to string.", obj->key);
			ret = -1;
			goto done;
		}
		assert(enc_data != NULL);

		data_size = strlen(enc_data);
		enc_bytes = (data_size >> 2) * 3;
		dec_data = NULL;
		dec_data = malloc((enc_bytes + 2) * sizeof(char));
		assert(dec_data != NULL);

		dec_bytes = EVP_DecodeBlock(dec_data, enc_data, data_size);
		assert(dec_bytes > 0);

		alloc_device_info_elem(list, (char *)obj->key, dec_data, NULL, (size_t)data_size);
	}

done:
	free(type);
	return (ret);
}

int
intern_arr_restore(const char *intern_arr_name, struct list_device_info *list,
		const ucl_object_t *obj)
{
	const ucl_object_t *param = NULL, *intern_obj = NULL;
	ucl_object_iter_t it = NULL, iit = NULL;
	int is_list;

	/* Check if the received instance contains an array */
	while ((param = ucl_object_iterate(obj, &it, true)) != NULL) {
		while ((intern_obj = ucl_object_iterate(param, &iit, true)) != NULL) {
			is_list = (ucl_object_type(intern_obj) == UCL_ARRAY);

			if (!is_list)
				restore_data(intern_obj, list);
			else
				intern_arr_restore(intern_obj->key, list, intern_obj);
		}
	}

	return (0);
}

int
lookup_check_dev(const char *dev_name, struct restore_state *rstate,
		 const ucl_object_t *obj,
		 struct list_device_info *list)
{
	const ucl_object_t *dev_params = NULL;
	const char *snapshot_req;

	snapshot_req = NULL;
	JSON_GET_STRING_OR_RETURN(JSON_SNAPSHOT_REQ_KEY, obj,
				  &snapshot_req, -EINVAL);
	assert(snapshot_req != NULL);

	if (!strcmp(snapshot_req, dev_name)) {
		dev_params = ucl_object_lookup(obj, JSON_PARAMS_KEY);
		if (dev_params == NULL) {
			fprintf(stderr, "Failed to find '%s' object.\n",
				JSON_PARAMS_KEY);
			return(-EINVAL);
		}

		if (ucl_object_type((ucl_object_t *)dev_params) != UCL_ARRAY) {
			fprintf(stderr, "Object '%s' is not an array.\n",
				JSON_PARAMS_KEY);
			return (-EINVAL);
		}

		/* Iterate through device parameters */
		intern_arr_restore(JSON_PARAMS_KEY, list, dev_params);

		return (0);
	}

	return (-1);
}

int
lookup_dev(const char *dev_name, struct restore_state *rstate,
		struct list_device_info *list)
{
	const ucl_object_t *devs = NULL, *obj = NULL;
	ucl_object_iter_t it = NULL;
	int ret;

	devs = ucl_object_lookup(rstate->meta_root_obj, JSON_DEV_ARR_KEY);
	if (devs == NULL) {
		fprintf(stderr, "Failed to find '%s' object.\n",
			JSON_DEV_ARR_KEY);
		return (-EINVAL);
	}

	if (ucl_object_type((ucl_object_t *)devs) != UCL_ARRAY) {
		fprintf(stderr, "Object '%s' is not an array.\n",
			JSON_DEV_ARR_KEY);
		return (-EINVAL);
	}

	while ((obj = ucl_object_iterate(devs, &it, true)) != NULL) {
		ret = lookup_check_dev(dev_name, rstate, obj, list);
		if (ret == 0)
			return (ret);
	}

	return (-1);
}

#else

static void *
lookup_check_dev(const char *dev_name, struct restore_state *rstate,
		 const ucl_object_t *obj, size_t *data_size)
{
	const char *snapshot_req;
	int64_t size, file_offset;

	snapshot_req = NULL;
	JSON_GET_STRING_OR_RETURN(JSON_SNAPSHOT_REQ_KEY, obj,
				  &snapshot_req, NULL);
	assert(snapshot_req != NULL);
	if (!strcmp(snapshot_req, dev_name)) {
		JSON_GET_INT_OR_RETURN(JSON_SIZE_KEY, obj,
				       &size, NULL);
		assert(size >= 0);

		JSON_GET_INT_OR_RETURN(JSON_FILE_OFFSET_KEY, obj,
				       &file_offset, NULL);
		assert(file_offset >= 0);
		assert(file_offset + size <= rstate->kdata_len);

		*data_size = (size_t)size;
		return (rstate->kdata_map + file_offset);
	}

	return (NULL);
}

static void*
lookup_dev(const char *dev_name, struct restore_state *rstate,
	   size_t *data_size)
{
	const ucl_object_t *devs = NULL, *obj = NULL;
	ucl_object_iter_t it = NULL;
	void *ret;

	devs = ucl_object_lookup(rstate->meta_root_obj, JSON_DEV_ARR_KEY);
	if (devs == NULL) {
		fprintf(stderr, "Failed to find '%s' object.\n",
			JSON_DEV_ARR_KEY);
		return (NULL);
	}

	if (ucl_object_type((ucl_object_t *)devs) != UCL_ARRAY) {
		fprintf(stderr, "Object '%s' is not an array.\n",
			JSON_DEV_ARR_KEY);
		return (NULL);
	}

	while ((obj = ucl_object_iterate(devs, &it, true)) != NULL) {
		ret = lookup_check_dev(dev_name, rstate, obj, data_size);
		if (ret != NULL)
			return (ret);
	}

	return (NULL);
}

#endif


static const ucl_object_t *
lookup_basic_metadata_object(struct restore_state *rstate)
{
	const ucl_object_t *basic_meta_obj = NULL;

	basic_meta_obj = ucl_object_lookup(rstate->meta_root_obj,
					   JSON_BASIC_METADATA_KEY);
	if (basic_meta_obj == NULL) {
		fprintf(stderr, "Failed to find '%s' object.\n",
			JSON_BASIC_METADATA_KEY);
		return (NULL);
	}

	if (ucl_object_type((ucl_object_t *)basic_meta_obj) != UCL_OBJECT) {
		fprintf(stderr, "Object '%s' is not a JSON object.\n",
		JSON_BASIC_METADATA_KEY);
		return (NULL);
	}

	return (basic_meta_obj);
}

const char *
lookup_vmname(struct restore_state *rstate)
{
	const char *vmname;
	const ucl_object_t *obj;

	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (NULL);

	JSON_GET_STRING_OR_RETURN(JSON_VMNAME_KEY, obj, &vmname, NULL);
	return (vmname);
}

int
lookup_memflags(struct restore_state *rstate)
{
	int64_t memflags;
	const ucl_object_t *obj;

	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (0);

	JSON_GET_INT_OR_RETURN(JSON_MEMFLAGS_KEY, obj, &memflags, 0);

	return ((int)memflags);
}

size_t
lookup_memsize(struct restore_state *rstate)
{
	int64_t memsize;
	const ucl_object_t *obj;

	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (0);

	JSON_GET_INT_OR_RETURN(JSON_MEMSIZE_KEY, obj, &memsize, 0);
	if (memsize < 0)
		memsize = 0;

	return ((size_t)memsize);
}


int
lookup_guest_ncpus(struct restore_state *rstate)
{
	int64_t ncpus;
	const ucl_object_t *obj;	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (0);

	JSON_GET_INT_OR_RETURN(JSON_NCPUS_KEY, obj, &ncpus, 0);
	return ((int)ncpus);
}

static void
winch_handler(int signal)
{
#ifdef TIOCGWINSZ
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize);
#endif /* TIOCGWINSZ */
}

static int
print_progress(size_t crtval, const size_t maxval)
{
	size_t rc;
	double crtval_gb, maxval_gb;
	size_t i, win_width, prog_start, prog_done, prog_end;
	int mval_len;

	static char prog_buf[PROG_BUF_SZ];
	static const size_t len = sizeof(prog_buf);

	static size_t div;
	static char *div_str;

	static char wip_bar[] = { '/', '-', '\\', '|' };
	static int wip_idx = 0;

	if (maxval == 0) {
		printf("[0B / 0B]\r\n");
		return (0);
	}

	if (crtval > maxval)
		crtval = maxval;

	if (maxval > 10 * GB) {
		div = GB;
		div_str = "GiB";
	} else if (maxval > 10 * MB) {
		div = MB;
		div_str = "MiB";
	} else {
		div = KB;
		div_str = "KiB";
	}

	crtval_gb = (double) crtval / div;
	maxval_gb = (double) maxval / div;

	rc = snprintf(prog_buf, len, "%.03lf", maxval_gb);
	if (rc == len) {
		fprintf(stderr, "Maxval too big\n");
		return (-1);
	}
	mval_len = rc;

	rc = snprintf(prog_buf, len, "\r[%*.03lf%s / %.03lf%s] |",
		mval_len, crtval_gb, div_str, maxval_gb, div_str);

	if (rc == len) {
		fprintf(stderr, "Buffer too small to print progress\n");
		return (-1);
	}

	win_width = min(winsize.ws_col, len);
	prog_start = rc;

	if (prog_start < (win_width - 2)) {
		prog_end = win_width - prog_start - 2;
		prog_done = prog_end * (crtval_gb / maxval_gb);

		for (i = prog_start; i < prog_start + prog_done; i++)
			prog_buf[i] = '#';

		if (crtval != maxval) {
			prog_buf[i] = wip_bar[wip_idx];
			wip_idx = (wip_idx + 1) % sizeof(wip_bar);
			i++;
		} else {
			prog_buf[i++] = '#';
		}

		for (; i < win_width - 2; i++)
			prog_buf[i] = '_';

		prog_buf[win_width - 2] = '|';
	}

	prog_buf[win_width - 1] = '\0';
	write(STDOUT_FILENO, prog_buf, win_width);

	return (0);
}

static void *
snapshot_spinner_cb(void *arg)
{
	int rc;
	size_t crtval, maxval, total;
	struct spinner_info *si;
	struct timespec ts;

	si = arg;
	if (si == NULL)
		pthread_exit(NULL);

	ts.tv_sec = 0;
	ts.tv_nsec = 50 * 1000 * 1000; /* 50 ms sleep time */

	do {
		crtval = *si->crtval;
		maxval = si->maxval;
		total = si->total;

		rc = print_progress(crtval, total);
		if (rc < 0) {
			fprintf(stderr, "Failed to parse progress\n");
			break;
		}

		nanosleep(&ts, NULL);
	} while (crtval < maxval);

	pthread_exit(NULL);
	return NULL;
}

static int
vm_snapshot_mem_part(const int snapfd, const size_t foff, void *src,
		     const size_t len, const size_t totalmem, const bool op_wr)
{
	int rc;
	size_t part_done, todo, rem;
	ssize_t done;
	bool show_progress;
	pthread_t spinner_th;
	struct spinner_info *si;

	if (lseek(snapfd, foff, SEEK_SET) < 0) {
		perror("Failed to change file offset");
		return (-1);
	}

	show_progress = false;
	if (isatty(STDIN_FILENO) && (winsize.ws_col != 0))
		show_progress = true;

	part_done = foff;
	rem = len;

	if (show_progress) {
		si = &(struct spinner_info) {
			.crtval = &part_done,
			.maxval = foff + len,
			.total = totalmem
		};

		rc = pthread_create(&spinner_th, 0, snapshot_spinner_cb, si);
		if (rc) {
			perror("Unable to create spinner thread");
			show_progress = false;
		}
	}

	while (rem > 0) {
		if (show_progress)
			todo = min(SNAPSHOT_CHUNK, rem);
		else
			todo = rem;

		if (op_wr)
			done = write(snapfd, src, todo);
		else
			done = read(snapfd, src, todo);
		if (done < 0) {
			perror("Failed to write in file");
			return (-1);
		}

		src += done;
		part_done += done;
		rem -= done;
	}

	if (show_progress) {
		rc = pthread_join(spinner_th, NULL);
		if (rc)
			perror("Unable to end spinner thread");
	}

	return (0);
}

static size_t
vm_snapshot_mem(struct vmctx *ctx, int snapfd, size_t memsz, const bool op_wr)
{
	int ret;
	size_t lowmem, highmem, totalmem;
	char *baseaddr;

	ret = vm_get_guestmem_from_ctx(ctx, &baseaddr, &lowmem, &highmem);
	if (ret) {
		fprintf(stderr, "%s: unable to retrieve guest memory size\r\n",
			__func__);
		return (0);
	}
	totalmem = lowmem + highmem;

	if ((op_wr == false) && (totalmem != memsz)) {
		fprintf(stderr, "%s: mem size mismatch: %ld vs %ld\r\n",
			__func__, totalmem, memsz);
		return (0);
	}

	winsize.ws_col = 80;
#ifdef TIOCGWINSZ
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize);
#endif /* TIOCGWINSZ */
	old_winch_handler = signal(SIGWINCH, winch_handler);

	ret = vm_snapshot_mem_part(snapfd, 0, baseaddr, lowmem,
		totalmem, op_wr);
	if (ret) {
		fprintf(stderr, "%s: Could not %s lowmem\r\n",
			__func__, op_wr ? "write" : "read");
		totalmem = 0;
		goto done;
	}

	if (highmem == 0)
		goto done;

	ret = vm_snapshot_mem_part(snapfd, lowmem, baseaddr + 4*GB,
		highmem, totalmem, op_wr);
	if (ret) {
		fprintf(stderr, "%s: Could not %s highmem\r\n",
		        __func__, op_wr ? "write" : "read");
		totalmem = 0;
		goto done;
	}

done:
	printf("\r\n");
	signal(SIGWINCH, old_winch_handler);

	return (totalmem);
}

int
restore_vm_mem(struct vmctx *ctx, struct restore_state *rstate)
{
	size_t restored;

	restored = vm_snapshot_mem(ctx, rstate->vmmem_fd, rstate->vmmem_len,
				   false);

	if (restored != rstate->vmmem_len)
		return (-1);

	return (0);
}

static int
vm_restore_kern_struct(struct vmctx *ctx, struct restore_state *rstate,
		       const struct vm_snapshot_kern_info *info)
{
	void *struct_ptr;
	size_t struct_size;
	int ret;
	struct vm_snapshot_meta *meta;

	struct_ptr = lookup_struct(info->req, rstate, &struct_size);
	if (struct_ptr == NULL) {
		fprintf(stderr, "%s: Failed to lookup struct %s\r\n",
			__func__, info->struct_name);
		ret = -1;
		goto done;
	}

	if (struct_size == 0) {
		fprintf(stderr, "%s: Kernel struct size was 0 for: %s\r\n",
			__func__, info->struct_name);
		ret = -1;
		goto done;
	}

	/*meta = &(struct vm_snapshot_meta) {
		.ctx = ctx,
		.dev_name = info->struct_name,
		.dev_req  = info->req,

		.buffer.buf_start = struct_ptr,
		.buffer.buf_size = struct_size,

		.buffer.buf = struct_ptr,
		.buffer.buf_rem = struct_size,

		.op = VM_SNAPSHOT_RESTORE,
#ifndef JSON_SNAPSHOT_V2
		.version = JSON_V1,
#else
		.version = JSON_V2,
		.dev_info_list.ident = 0,
		.dev_info_list.first = NULL,
		.dev_info_list.last = NULL,
#endif
	};*/
	meta = &(struct vm_snapshot_meta) {
		.ctx = ctx,
		.dev_name = info->struct_name,
		.dev_req  = info->req,

		.buffer.buf_start = struct_ptr,
		.buffer.buf_size = struct_size,

		.buffer.buf = struct_ptr,
		.buffer.buf_rem = struct_size,

		.op = VM_SNAPSHOT_RESTORE,
		.version = JSON_V1,
	};

	ret = vm_snapshot_req(meta);
	if (ret != 0) {
		fprintf(stderr, "%s: Failed to restore struct: %s\r\n",
			__func__, info->struct_name);
		goto done;
	}

done:
	return (ret);
}

int
vm_restore_kern_structs(struct vmctx *ctx, struct restore_state *rstate)
{
	int ret;
	int i;

	for (i = 0; i < nitems(snapshot_kern_structs); i++) {
		ret = vm_restore_kern_struct(ctx, rstate,
					     &snapshot_kern_structs[i]);
		if (ret != 0)
			return (ret);
	}

	return (0);
}

#ifdef JSON_SNAPSHOT_V2

int
vm_restore_user_dev(struct vmctx *ctx, struct restore_state *rstate,
		    const struct vm_snapshot_dev_info *info)
{
	int ret;
	struct list_device_info list;
	struct vm_snapshot_meta *meta;
	
	memset(&list, 0, sizeof(list));
	list.first = NULL;
	list.last = NULL;

	ret = lookup_dev(info->dev_name, rstate, &list);
	if (ret != 0) {
		fprintf(stderr, "Failed to lookup dev: %s\r\n", info->dev_name);
		fprintf(stderr, "Continuing the restore/migration process\r\n");
		return (0);
	}

	meta = &(struct vm_snapshot_meta) {
		.ctx = ctx,
		.dev_name = info->dev_name,

		.op = VM_SNAPSHOT_RESTORE,

		.version = JSON_V2,
		.dev_info_list.ident = 0,
		.dev_info_list.first = list.first,
		.dev_info_list.last = list.last,
	};
	
	ret = (*info->snapshot_cb)(meta);
	if (ret != 0) {
		fprintf(stderr, "Failed to restore dev: %s\r\n",
			info->dev_name);
		return (-1);
	}

	return (0);
}

#else

int
vm_restore_user_dev(struct vmctx *ctx, struct restore_state *rstate,
		    const struct vm_snapshot_dev_info *info)
{
	void *dev_ptr;
	size_t dev_size;
	int ret;
	struct vm_snapshot_meta *meta;

	dev_ptr = lookup_dev(info->dev_name, rstate, &dev_size);
	if (dev_ptr == NULL) {
		fprintf(stderr, "Failed to lookup dev: %s\r\n", info->dev_name);
		fprintf(stderr, "Continuing the restore/migration process\r\n");
		return (0);
	}

	if (dev_size == 0) {
		fprintf(stderr, "%s: Device size is 0. "
			"Assuming %s is not used\r\n",
			__func__, info->dev_name);
		return (0);
	}	

	meta = &(struct vm_snapshot_meta) {
		.ctx = ctx,
		.dev_name = info->dev_name,

		.buffer.buf_start = dev_ptr,
		.buffer.buf_size = dev_size,

		.buffer.buf = dev_ptr,
		.buffer.buf_rem = dev_size,

		.op = VM_SNAPSHOT_RESTORE,
		.version = JSON_V1,
	};

	ret = (*info->snapshot_cb)(meta);
	if (ret != 0) {
		fprintf(stderr, "Failed to restore dev: %s\r\n",
			info->dev_name);
		return (-1);
	}

	return (0);
}

#endif

int
vm_restore_user_devs(struct vmctx *ctx, struct restore_state *rstate)
{
	int ret;
	int i;

	for (i = 0; i < nitems(snapshot_devs); i++) {
		ret = vm_restore_user_dev(ctx, rstate, &snapshot_devs[i]);
		if (ret != 0)
			return (ret);
		fprintf(stderr, "%s restored successfully\r\n", snapshot_devs[i].dev_name);
	}

	return 0;
}

int
vm_pause_user_devs(struct vmctx *ctx)
{
	const struct vm_snapshot_dev_info *info;
	int ret;
	int i;

	for (i = 0; i < nitems(snapshot_devs); i++) {
		info = &snapshot_devs[i];
		if (info->pause_cb == NULL)
			continue;

		ret = info->pause_cb(ctx, info->dev_name);
		if (ret != 0)
			return (ret);
	}

	return (0);
}

int
vm_resume_user_devs(struct vmctx *ctx)
{
	const struct vm_snapshot_dev_info *info;
	int ret;
	int i;

	for (i = 0; i < nitems(snapshot_devs); i++) {
		info = &snapshot_devs[i];
		if (info->resume_cb == NULL)
			continue;

		ret = info->resume_cb(ctx, info->dev_name);
		if (ret != 0)
			return (ret);
	}

	return (0);
}

static int
vm_snapshot_kern_struct(int data_fd, xo_handle_t *xop, const char *array_key,
			struct vm_snapshot_meta *meta, off_t *offset)
{
	int ret;
	size_t data_size;
	ssize_t write_cnt;

	struct vm_snapshot_device_info *curr_el;

	ret = vm_snapshot_req(meta);
	if (ret != 0) {
		fprintf(stderr, "%s: Failed to snapshot struct %s\r\n",
			__func__, meta->dev_name);
		ret = -1;
		goto done;
	}
	/* TODO - Be carefull here */
	if (!strcmp(meta->dev_name, "vhpet"))
		vhpet_snapshot(meta);
	else if (!strcmp(meta->dev_name, "vm"))
		vm_snapshot_vm(meta);
	else if (!strcmp(meta->dev_name, "vlapic"))
		vlapic_snapshot(meta);
	else if (!strcmp(meta->dev_name, "vioapic"))
		vioapic_snapshot(meta);
	else if (!strcmp(meta->dev_name, "vatpit"))
		vatpit_snapshot(meta);
	else if (!strcmp(meta->dev_name, "vatpic"))
		vatpic_snapshot(meta);
	else if (!strcmp(meta->dev_name, "vpmtmr"))
		vpmtmr_snapshot(meta);
	else if (!strcmp(meta->dev_name, "vrtc"))
		vrtc_snapshot(meta);

	data_size = vm_get_snapshot_size(meta);

	write_cnt = write(data_fd, meta->buffer.buf_start, data_size);
	if (write_cnt != data_size) {
		perror("Failed to write all snapshotted data.");
		ret = -1;
		goto done;
	}
	fprintf(stderr, "%s: %s has size %ld\r\n", __func__, meta->dev_name, data_size);

	/* Write metadata. */
	//xo_open_instance_h(xop, array_key);
	//xo_emit_h(xop, "{:debug_name/%s}\n", meta->dev_name);
	//xo_emit_h(xop, "{:" JSON_SNAPSHOT_REQ_KEY "/%d}\n", meta->dev_req);
	//xo_emit_h(xop, "{:" JSON_SIZE_KEY "/%lu}\n", data_size);
	//xo_emit_h(xop, "{:" JSON_FILE_OFFSET_KEY "/%lu}\n", *offset);
	//xo_close_instance_h(xop, JSON_STRUCT_ARR_KEY);
	//xo_close_instance_h(xop, array_key);

	//*offset += data_size;
	
	xo_open_instance_h(xop, array_key);
	xo_emit_h(xop, "{:debug_name/%s}\n", meta->dev_name);
	//xo_emit_h(xop, "{:" JSON_SNAPSHOT_REQ_KEY "/%s}\n", meta->dev_req);
	if (meta->version == JSON_V1) {
		xo_emit_h(xop, "{:" JSON_SIZE_KEY "/%lu}\n", data_size);
		xo_emit_h(xop, "{:" JSON_FILE_OFFSET_KEY "/%lu}\n", *offset);
	}
	if (meta->version == JSON_V2) {
		curr_el = meta->dev_info_list.first;
		meta->dev_info_list.ident = 0;

		xo_open_list_h(xop, JSON_PARAMS_KEY);
		xo_open_instance_h(xop, JSON_PARAMS_KEY);
		while (curr_el != NULL) {
			if (curr_el->ident > meta->dev_info_list.ident) {
				vm_snapshot_dev_intern_arr(xop, curr_el->ident, curr_el->index, &curr_el);
				continue;
			}
			
			emit_data(xop, curr_el);

			curr_el = curr_el->next_field;
		}
		xo_close_instance_h(xop, JSON_PARAMS_KEY);
		xo_close_list_h(xop, JSON_PARAMS_KEY);
	}
	xo_close_instance_h(xop, array_key);
done:
	return (ret);
}

static int
vm_snapshot_kern_structs(struct vmctx *ctx, int data_fd, xo_handle_t *xop)
{
	int ret, i, error;
	size_t offset, buf_size;
	char *buffer;
	struct vm_snapshot_meta *meta;

	error = 0;
	offset = 0;
	buf_size = SNAPSHOT_BUFFER_SIZE;

	buffer = malloc(SNAPSHOT_BUFFER_SIZE * sizeof(char));
	if (buffer == NULL) {
		error = ENOMEM;
		perror("Failed to allocate memory for snapshot buffer");
		goto err_vm_snapshot_kern_data;
	}

	meta = &(struct vm_snapshot_meta) {
		.ctx = ctx,

		.buffer.buf_start = buffer,
		.buffer.buf_size = buf_size,

		.op = VM_SNAPSHOT_SAVE,
#ifdef JSON_SNAPSHOT_V2
		.version = JSON_V2,
		.dev_info_list.ident = 0,
		.dev_info_list.index = -1,
		.dev_info_list.create_instance = 1,  
		.dev_info_list.auto_index = -1,
		.dev_info_list.first = NULL,
		.dev_info_list.last = NULL,
		.snapshot_kernel = 1,
#else
		.version = JSON_V1,
#endif
	};

	/* meta = &(struct vm_snapshot_meta) {
		.ctx = ctx,

		.buffer.buf_start = buffer,
		.buffer.buf_size = buf_size,

		.op = VM_SNAPSHOT_SAVE,
		.version = JSON_V1,
	};*/

	/* Prepare types hashtable */
	ret = create_types_hashtable();

	xo_open_list_h(xop, JSON_STRUCT_ARR_KEY);
	for (i = 0; i < nitems(snapshot_kern_structs); i++) {
		meta->dev_name = snapshot_kern_structs[i].struct_name;
		meta->dev_req  = snapshot_kern_structs[i].req;

		memset(meta->buffer.buf_start, 0, meta->buffer.buf_size);
		meta->buffer.buf = meta->buffer.buf_start;
		meta->buffer.buf_rem = meta->buffer.buf_size;

		free_device_info_list(&meta->dev_info_list);

		ret = vm_snapshot_kern_struct(data_fd, xop, JSON_STRUCT_ARR_KEY, meta, &offset);
		if (ret != 0) {
			error = -1;
			goto err_vm_snapshot_kern_data;
		}
	}
	xo_close_list_h(xop, JSON_STRUCT_ARR_KEY);

err_vm_snapshot_kern_data:
	if (buffer != NULL)
		free(buffer);
	return (error);
}

static int
vm_snapshot_basic_metadata(struct vmctx *ctx, xo_handle_t *xop, size_t memsz)
{
	int error;
	int memflags;
	char vmname_buf[MAX_VMNAME];

	memset(vmname_buf, 0, MAX_VMNAME);
	error = vm_get_name(ctx, vmname_buf, MAX_VMNAME - 1);
	if (error != 0) {
		perror("Failed to get VM name");
		goto err;
	}

	memflags = vm_get_memflags(ctx);

	xo_open_container_h(xop, JSON_BASIC_METADATA_KEY);
	xo_emit_h(xop, "{:" JSON_NCPUS_KEY "/%ld}\n", guest_ncpus);
	xo_emit_h(xop, "{:" JSON_VMNAME_KEY "/%s}\n", vmname_buf);
	xo_emit_h(xop, "{:" JSON_MEMSIZE_KEY "/%lu}\n", memsz);
	xo_emit_h(xop, "{:" JSON_MEMFLAGS_KEY "/%d}\n", memflags);
#ifndef JSON_SNAPSHOT_V2
	xo_emit_h(xop, "{:" JSON_VERSION_KEY "/%d}\n", JSON_V1);
#else
	xo_emit_h(xop, "{:" JSON_VERSION_KEY "/%d}\n", JSON_V2);
#endif
	xo_close_container_h(xop, JSON_BASIC_METADATA_KEY);

err:
	return (error);
}

#ifdef JSON_SNAPSHOT_V2

static int
create_indexed_arr_name(char *intern_arr, int number, char **indexed_name)
{
	int ret;

	ret = asprintf(indexed_name, "%s@%d", intern_arr, number);

	if (ret < 0)
		fprintf(stderr, "%s: Could not alloc memory at line %d\r\n", __func__, __LINE__);

	return (ret);
}

static int
create_type_info(struct type_info **ti, const char *name,
		const char *fmt_str, unsigned char size)
{
	int ret;

	ret = 0;

	*ti = calloc(1, sizeof(struct type_info));
	if (*ti == NULL) {
		fprintf(stderr, "%s: Could not alloc memory at line %d\r\n", __func__, __LINE__);
		ret = ENOMEM;
	}

	strcpy((*ti)->type_name, name);
	strcpy((*ti)->fmt_str, fmt_str);
	(*ti)->size = size;

	return (ret);
}

static int
create_types_hashtable()
{
	int ret, i, j;
	struct type_info *ti;
	ENTRY item;
	ENTRY *res = NULL;
	const char *types[] = { "int8", "uint8", "int16", "uint16",
							"int32", "uint32", "int64", "uint64" };

	const char *fmt_strs[] = { "/%%hhd}\\n", "/%%hhu}\\n", "/%%hd}\\n",
		"/%%hu}\\n", "/%%d}\\n", "/%%u}\\n", "/%%lld}\\n", "/%%llu}\\b" };

	const unsigned char type_sizes[] = { sizeof(int8_t), sizeof(uint8_t),
										 sizeof(int16_t), sizeof(uint16_t),
										 sizeof(int32_t), sizeof(uint32_t),
										 sizeof(int64_t), sizeof(uint64_t) };
	ret = 0;

	types_htable = calloc(1, sizeof(*types_htable));
	if (types_htable == NULL) {
		fprintf(stderr, "%s: Could not alloc memory at line %d\r\n", __func__, __LINE__);
		ret = ENOMEM;
		goto done;
	}

	if(!hcreate_r(32, types_htable)) {
		ret = errno;
		goto done;
	}

	for (i = 0; i < 8; ++i) {
		ret = create_type_info(&ti, types[i], fmt_strs[i], type_sizes[i]);

		if (ret != 0) {
			j = i;
			goto done;
		}

		item.key = (char *)ti->type_name;
		item.data = ti;
		if (!hsearch_r(item, ENTER, &res, types_htable)) {
			j = i;
			fprintf(stderr, "%s: Could not add data into hashtable(line %d)\r\n",
					__func__, __LINE__);
			ret = errno;
			goto done;
		}
	}

	return (ret);

done:
	free(types_htable);
	types_htable = NULL;

	for (i = 0; i < j; ++i) {
		item.key = (char *)types[i];
		if (!hsearch_r(item, FIND, &res, types_htable)) {
			fprintf(stderr,
					"%s: Could not find key %s in hashtable(line %d)\r\n",
					__func__, item.key, __LINE__);
			continue;
		}
		free(res->data);
	}
	hdestroy_r(types_htable);

	return (ret);
}

static void
destroy_types_hashtable()
{
	int i;
	ENTRY item;
	ENTRY *res = NULL;
	const char *types[] = { "int8", "uint8", "int16", "uint16",
							"int32", "uint32", "int64", "uint64" };

	for (i = 0; i < 8; ++i) {
		item.key = (char *)types[i];
		if (!hsearch_r(item, FIND, &res, types_htable)) {
			fprintf(stderr,
					"%s: Could not find key %s in hashtable(line %d)\r\n",
					__func__, item.key, __LINE__);
			continue;
		}
		
		free(res->data);
	}

	hdestroy_r(types_htable);
}

static int
get_type_format_string(char **res, char *key_part, char *type)
{
	int ret;
	struct type_info *ti;
	ENTRY item;
	ENTRY *ires = NULL;

	item.key = type;
	if (hsearch_r(item, FIND, &ires, types_htable)) {
		ti = (struct type_info *)(ires->data);
		ret = asprintf(res, "%s%s", key_part, ti->fmt_str);
	} else
		ret = asprintf(res, "%s%s", key_part, "/%%s}\\n");

	if (ret < 0)
		fprintf(stderr, "%s: Could not alloc memory at line %d\r\n", __func__, __LINE__);

	return (ret);
}

static int
create_key_string(struct vm_snapshot_device_info *elem, char **res_str)
{
	int ret;
	char *fmt = NULL;

	ret = 0;
	if (!elem->create_instance && (elem->index != -1)) {
		ret = get_type_format_string(&fmt, "{:%s%d$%s", elem->type);
		ret = asprintf(res_str, fmt, elem->field_name, elem->index, elem->type);
	} else {
		ret = get_type_format_string(&fmt, "{:%s$%s", elem->type);
		ret = asprintf(res_str, fmt, elem->field_name, elem->type);
	}

	free(fmt);
	return (ret);
}

static int
emit_data(xo_handle_t *xop, struct vm_snapshot_device_info *elem)
{
	int ret;
	char *enc_data = NULL;
	char *fmt;
	int enc_bytes = 0;
	int64_t int_data;

	unsigned long ds;

	ENTRY item;
	ENTRY *res = NULL;

	ret = 0;
	create_key_string(elem, &fmt);
	
	item.key = elem->type;
	if (hsearch_r(item, FIND, &res, types_htable)) {
		memcpy(&int_data, elem->field_data,
				((struct type_info *)res->data)->size);
		xo_emit_h(xop, fmt, int_data);
	} else {
		ds = elem->data_size;
		enc_data = malloc(4 * (ds + 2) / 3);
		assert(enc_data != NULL);

		enc_bytes = EVP_EncodeBlock(enc_data, (const char *)elem->field_data, ds);
		assert(enc_bytes != 0);

		xo_emit_h(xop, fmt, enc_data);

		free(enc_data);
	}

	free(fmt);
	return (ret);
}

static int
vm_snapshot_dev_intern_arr_index(xo_handle_t *xop, int ident, int index,
				struct vm_snapshot_device_info **curr_el)
{
	char *intern_arr = NULL;
	char *indexed_name = NULL;
	int ret = 0;

	intern_arr = (*curr_el)->intern_arr_name;

	create_indexed_arr_name(intern_arr, index, &indexed_name);
	xo_open_list_h(xop, indexed_name);

	xo_open_instance_h(xop, indexed_name);
	while (*curr_el != NULL) {
		/* Check if there is an internal array */
		if ((*curr_el)->ident > ident) {
			ret = vm_snapshot_dev_intern_arr(xop, (*curr_el)->ident, (*curr_el)->index, curr_el);
			continue;
		}

		/* Check if index changed and if there is no array at the same 
		 * indentation level as the current one for this index */
		if ((index != (*curr_el)->index) && (ret == 0))
			break;

		/* Reset the return value for the first branch inside the loop */
		ret = 0;

		/* Write data */
		emit_data(xop, *curr_el);

		*curr_el = (*curr_el)->next_field;
	}

	xo_close_instance_h(xop, indexed_name);
	xo_close_list_h(xop, indexed_name);
	free(indexed_name);
	indexed_name = NULL;

	return (ret);
}

static int
vm_snapshot_dev_intern_arr(xo_handle_t *xop, int ident, int index,
				struct vm_snapshot_device_info **curr_el)
{
	char *intern_arr = NULL;
	int ret = 0;

	intern_arr = (*curr_el)->intern_arr_name;
	xo_open_list_h(xop, intern_arr);

	xo_open_instance_h(xop, intern_arr);
	while (*curr_el != NULL) {
		/* Check if the current array has no more elements */
		if ((*curr_el)->ident < ident)
			break;

		/* Check if there is an array on the same indentation level */
		if (strcmp((*curr_el)->intern_arr_name, intern_arr) &&
			(*curr_el)->ident == ident &&
			ret == 0) {
			ret = 1;
			break;
		}

		/* Check if there is an internal array */
		if ((*curr_el)->ident > ident) {
			ret = vm_snapshot_dev_intern_arr(xop, (*curr_el)->ident, (*curr_el)->index, curr_el);
			continue;
		}

		/* Check if for the current array indexing is present */
		if (((*curr_el)->index != -1) && ((*curr_el)->create_instance == 1)) {
			vm_snapshot_dev_intern_arr_index(xop, (*curr_el)->ident, (*curr_el)->index, curr_el);
			continue;
		}

		ret = 0;
		/* Write data inside the array */
		emit_data(xop, *curr_el);

		*curr_el = (*curr_el)->next_field;
	}
	xo_close_instance_h(xop, intern_arr);
	xo_close_list_h(xop, intern_arr);

	return (ret);
}
#endif

static int
vm_snapshot_dev_write_data(int data_fd, xo_handle_t *xop, const char *array_key,
			   struct vm_snapshot_meta *meta, off_t *offset)
{
	int ret;
	size_t data_size;

	struct vm_snapshot_device_info *curr_el;

	data_size = vm_get_snapshot_size(meta);

	if (meta->version == JSON_V1) {
		ret = write(data_fd, meta->buffer.buf_start, data_size);
		if (ret != data_size) {
			perror("Failed to write all snapshotted data.");
			return (-1);
		}
		*offset += data_size;
	}

	/* Write metadata. */
	xo_open_instance_h(xop, array_key);
	xo_emit_h(xop, "{:" JSON_SNAPSHOT_REQ_KEY "/%s}\n", meta->dev_name);
	if (meta->version == JSON_V1) {
		xo_emit_h(xop, "{:" JSON_SIZE_KEY "/%lu}\n", data_size);
		xo_emit_h(xop, "{:" JSON_FILE_OFFSET_KEY "/%lu}\n", *offset);
	}
	if (meta->version == JSON_V2) {
		curr_el = meta->dev_info_list.first;
		meta->dev_info_list.ident = 0;

		xo_open_list_h(xop, JSON_PARAMS_KEY);
		xo_open_instance_h(xop, JSON_PARAMS_KEY);
		while (curr_el != NULL) {
			if (curr_el->ident > meta->dev_info_list.ident) {
				vm_snapshot_dev_intern_arr(xop, curr_el->ident, curr_el->index, &curr_el);
				continue;
			}

			emit_data(xop, curr_el);

			curr_el = curr_el->next_field;
		}
		xo_close_instance_h(xop, JSON_PARAMS_KEY);
		xo_close_list_h(xop, JSON_PARAMS_KEY);
	}
	xo_close_instance_h(xop, array_key);

	return (0);
}

static int
vm_snapshot_user_dev(const struct vm_snapshot_dev_info *info,
		     int data_fd, xo_handle_t *xop,
		     struct vm_snapshot_meta *meta, off_t *offset)
{
	int ret;

	ret = (*info->snapshot_cb)(meta);
	if (ret != 0) {
		fprintf(stderr, "Failed to snapshot %s; ret=%d\r\n",
			meta->dev_name, ret);
		return (ret);
	}

	if (meta->version == JSON_V2)
		if (meta->dev_info_list.first == NULL)
			return (0);

	ret = vm_snapshot_dev_write_data(data_fd, xop, JSON_DEV_ARR_KEY, meta,
					 offset);
	if (ret != 0)
		return (ret);

	return (0);
}

static int
vm_snapshot_user_devs(struct vmctx *ctx, int data_fd, xo_handle_t *xop)
{
	int ret, i;

	off_t offset;
#ifndef JSON_SNAPSHOT_V2
	void *buffer;
	size_t buf_size;
#endif

	struct vm_snapshot_meta *meta;

#ifndef JSON_SNAPSHOT_V2
	buf_size = SNAPSHOT_BUFFER_SIZE;

	offset = lseek(data_fd, 0, SEEK_CUR);
	if (offset < 0) {
		perror("Failed to get data file current offset.");
		return (-1);
	}

	buffer = malloc(buf_size);
	if (buffer == NULL) {
		perror("Failed to allocate memory for snapshot buffer");
		ret = ENOSPC;
		goto snapshot_err;
	}
#endif
	offset = 0;
	meta = &(struct vm_snapshot_meta) {
		.ctx = ctx,

		.op = VM_SNAPSHOT_SAVE,

#ifndef JSON_SNAPSHOT_V2
		.buffer.buf_start = buffer,
		.buffer.buf_size = buf_size,
		.version = JSON_V1,
#else
		.version = JSON_V2,
		.dev_info_list.ident = 0,
		.dev_info_list.index = -1,
		.dev_info_list.create_instance = 1,  
		.dev_info_list.auto_index = -1,
		.dev_info_list.first = NULL,
		.dev_info_list.last = NULL,
#endif
	};

	/* Prepare the hashtable for types */
	ret = create_types_hashtable();
	if (ret != 0)
		goto snapshot_err;

	xo_open_list_h(xop, JSON_DEV_ARR_KEY);

	/* Restore other devices that support this feature */
	for (i = 0; i < nitems(snapshot_devs); i++) {
		fprintf(stderr, "Creating snapshot for %s device\r\n", snapshot_devs[i].dev_name);
		meta->dev_name = snapshot_devs[i].dev_name;

		if (meta->version == JSON_V1) {
			memset(meta->buffer.buf_start, 0, meta->buffer.buf_size);
			meta->buffer.buf = meta->buffer.buf_start;
			meta->buffer.buf_rem = meta->buffer.buf_size;
		} else if (meta->version == JSON_V2)
			free_device_info_list(&meta->dev_info_list);

		ret = vm_snapshot_user_dev(&snapshot_devs[i], data_fd, xop,
					   meta, &offset);
		if (ret != 0)
			goto snapshot_err;
	}

	xo_close_list_h(xop, JSON_DEV_ARR_KEY);

	/* Clear types hashtable */
	destroy_types_hashtable();

snapshot_err:
#ifndef JSON_SNAPSHOT_V2
	if (buffer != NULL)
		free(buffer);
#endif

	return (ret);
}

void
checkpoint_cpu_add(int vcpu)
{

	pthread_mutex_lock(&vcpu_lock);
	CPU_SET(vcpu, &vcpus_active);

	if (checkpoint_active) {
		CPU_SET(vcpu, &vcpus_suspended);
		while (checkpoint_active)
			pthread_cond_wait(&vcpus_can_run, &vcpu_lock);
		CPU_CLR(vcpu, &vcpus_suspended);
	}
	pthread_mutex_unlock(&vcpu_lock);
}

/*
 * When a vCPU is suspended for any reason, it calls
 * checkpoint_cpu_suspend().  This records that the vCPU is idle.
 * Before returning from suspension, checkpoint_cpu_resume() is
 * called.  In suspend we note that the vCPU is idle.  In resume we
 * pause the vCPU thread until the checkpoint is complete.  The reason
 * for the two-step process is that vCPUs might already be stopped in
 * the debug server when a checkpoint is requested.  This approach
 * allows us to account for and handle those vCPUs.
 */
void
checkpoint_cpu_suspend(int vcpu)
{

	pthread_mutex_lock(&vcpu_lock);
	CPU_SET(vcpu, &vcpus_suspended);
	if (checkpoint_active && CPU_CMP(&vcpus_active, &vcpus_suspended) == 0)
		pthread_cond_signal(&vcpus_idle);
	pthread_mutex_unlock(&vcpu_lock);
}

void
checkpoint_cpu_resume(int vcpu)
{

	pthread_mutex_lock(&vcpu_lock);
	while (checkpoint_active)
		pthread_cond_wait(&vcpus_can_run, &vcpu_lock);
	CPU_CLR(vcpu, &vcpus_suspended);
	pthread_mutex_unlock(&vcpu_lock);
}

static void
vm_vcpu_pause(struct vmctx *ctx)
{

	pthread_mutex_lock(&vcpu_lock);
	checkpoint_active = true;
	vm_suspend_cpu(ctx, -1);
	while (CPU_CMP(&vcpus_active, &vcpus_suspended) != 0)
		pthread_cond_wait(&vcpus_idle, &vcpu_lock);
	pthread_mutex_unlock(&vcpu_lock);
}

static void
vm_vcpu_resume(struct vmctx *ctx)
{

	pthread_mutex_lock(&vcpu_lock);
	checkpoint_active = false;
	pthread_mutex_unlock(&vcpu_lock);
	vm_resume_cpu(ctx, -1);
	pthread_cond_broadcast(&vcpus_can_run);
}

static int
vm_checkpoint(struct vmctx *ctx, char *checkpoint_file, bool stop_vm)
{
	int fd_checkpoint = 0, kdata_fd = 0;
	int ret = 0;
	int error = 0;
	size_t memsz;
	xo_handle_t *xop = NULL;
	char *meta_filename = NULL;
	char *kdata_filename = NULL;
	FILE *meta_file = NULL;

	kdata_filename = strcat_extension(checkpoint_file, ".kern");
	if (kdata_filename == NULL) {
		fprintf(stderr, "Failed to construct kernel data filename.\n");
		return (-1);
	}

	kdata_fd = open(kdata_filename, O_WRONLY | O_CREAT | O_TRUNC, 0700);
	if (kdata_fd < 0) {
		perror("Failed to open kernel data snapshot file.");
		error = -1;
		goto done;
	}

	fd_checkpoint = open(checkpoint_file, O_RDWR | O_CREAT | O_TRUNC, 0700);

	if (fd_checkpoint < 0) {
		perror("Failed to create checkpoint file");
		error = -1;
		goto done;
	}

	meta_filename = strcat_extension(checkpoint_file, ".meta");
	if (meta_filename == NULL) {
		fprintf(stderr, "Failed to construct vm metadata filename.\n");
		goto done;
	}

	meta_file = fopen(meta_filename, "w");
	if (meta_file == NULL) {
		perror("Failed to open vm metadata snapshot file.");
		goto done;
	}

	xop = xo_create_to_file(meta_file, XO_STYLE_JSON, XOF_PRETTY);
	if (xop == NULL) {
		perror("Failed to get libxo handle on metadata file.");
		goto done;
	}

	vm_vcpu_pause(ctx);

	ret = vm_pause_user_devs(ctx);
	if (ret != 0) {
		fprintf(stderr, "Could not pause devices\r\n");
		error = ret;
		goto done;
	}

	memsz = vm_snapshot_mem(ctx, fd_checkpoint, 0, true);
	if (memsz == 0) {
		perror("Could not write guest memory to file");
		error = -1;
		goto done;
	}

	ret = vm_snapshot_basic_metadata(ctx, xop, memsz);
	if (ret != 0) {
		fprintf(stderr, "Failed to snapshot vm basic metadata.\n");
		error = -1;
		goto done;
	}


	ret = vm_snapshot_kern_structs(ctx, kdata_fd, xop);
	if (ret != 0) {
		fprintf(stderr, "Failed to snapshot vm kernel data.\n");
		error = -1;
		goto done;
	}

	ret = vm_snapshot_user_devs(ctx, kdata_fd, xop);
	if (ret != 0) {
		fprintf(stderr, "Failed to snapshot device state.\n");
		error = -1;
		goto done;
	}

	xo_finish_h(xop);

	if (stop_vm) {
		vm_destroy(ctx);
		exit(0);
	}

done:
	ret = vm_resume_user_devs(ctx);
	if (ret != 0)
		fprintf(stderr, "Could not resume devices\r\n");
	vm_vcpu_resume(ctx);
	if (fd_checkpoint > 0)
		close(fd_checkpoint);
	if (meta_filename != NULL)
		free(meta_filename);
	if (kdata_filename != NULL)
		free(kdata_filename);
	if (xop != NULL)
		xo_destroy(xop);
	if (meta_file != NULL)
		fclose(meta_file);
	if (kdata_fd > 0)
		close(kdata_fd);
	return (error);
}

int
handle_message(struct checkpoint_op *checkpoint_op, struct vmctx *ctx)
{
	int err;

	switch (checkpoint_op->op) {
		case START_CHECKPOINT:
			err = vm_checkpoint(ctx, checkpoint_op->snapshot_filename, false);
			break;
		case START_SUSPEND:
			err = vm_checkpoint(ctx, checkpoint_op->snapshot_filename, true);
			break;
		default:
			EPRINTLN("Unrecognized checkpoint operation\n");
			err = -1;
	}

	if (err != 0)
		EPRINTLN("Unable to perform the requested operation\n");

	return (err);
}

/*
 * Listen for commands from bhyvectl
 */
void *
checkpoint_thread(void *param)
{
	struct checkpoint_op op;
	struct checkpoint_thread_info *thread_info;
	ssize_t n;

	pthread_set_name_np(pthread_self(), "checkpoint thread");
	thread_info = (struct checkpoint_thread_info *)param;

	for (;;) {
		n = recvfrom(thread_info->socket_fd, &op, sizeof(op), 0, NULL, 0);

		/*
		 * slight sanity check: see if there's enough data to at
		 * least determine the type of message.
		 */
		if (n >= sizeof(op.op))
			handle_message(&op, thread_info->ctx);
		else
			EPRINTLN("Failed to receive message: %s\n",
			    n == -1 ? strerror(errno) : "unknown error");
	}

	return (NULL);
}

/*
 * Create the listening socket for IPC with bhyvectl
 */
int
init_checkpoint_thread(struct vmctx *ctx)
{
	struct checkpoint_thread_info *checkpoint_info = NULL;
	struct sockaddr_un addr;
	int socket_fd;
	pthread_t checkpoint_pthread;
	char vmname_buf[MAX_VMNAME];
	int ret, err = 0;

	memset(&addr, 0, sizeof(addr));

	err = pthread_mutex_init(&vcpu_lock, NULL);
	if (err != 0)
		errc(1, err, "checkpoint mutex init");
	err = pthread_cond_init(&vcpus_idle, NULL);
	if (err == 0)
		err = pthread_cond_init(&vcpus_can_run, NULL);
	if (err != 0)
		errc(1, err, "checkpoint cv init");

	socket_fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (socket_fd < 0) {
		EPRINTLN("Socket creation failed: %s", strerror(errno));
		err = -1;
		goto fail;
	}

	addr.sun_family = AF_UNIX;

	err = vm_get_name(ctx, vmname_buf, MAX_VMNAME - 1);
	if (err != 0) {
		perror("Failed to get VM name");
		goto fail;
	}

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s%s",
		 BHYVE_RUN_DIR, vmname_buf);
	addr.sun_len = SUN_LEN(&addr);
	unlink(addr.sun_path);

	if (bind(socket_fd, (struct sockaddr *)&addr, addr.sun_len) != 0) {
		EPRINTLN("Failed to bind socket \"%s\": %s\n",
		    addr.sun_path, strerror(errno));
		err = -1;
		goto fail;
	}

	checkpoint_info = calloc(1, sizeof(*checkpoint_info));
	checkpoint_info->ctx = ctx;
	checkpoint_info->socket_fd = socket_fd;

	ret = pthread_create(&checkpoint_pthread, NULL, checkpoint_thread,
		checkpoint_info);
	if (ret < 0) {
		err = ret;
		goto fail;
	}

	return (0);
fail:
	free(checkpoint_info);
	if (socket_fd > 0)
		close(socket_fd);
	unlink(addr.sun_path);

	return (err);
}

int
vm_snapshot_save_fieldname(const char *fullname, volatile void *data,
				char *type, size_t data_size, struct vm_snapshot_meta *meta)
{
	int ret;
	size_t len;
	char *ffield_name;
	char *aux;
    char *field_name;
	void *kdata = NULL;
	int op;
	struct vm_snapshot_buffer *buffer;
	struct list_device_info *list;
	struct vm_snapshot_device_info *aux_elem;
    const char delim[5] = "&(>)";

	if (meta->snapshot_kernel)
		if (buffer->buf_rem < data_size) {
			fprintf(stderr, "%s: buffer too small\r\n", __func__);
			return (E2BIG);
		}

	ret = 0;
	op = meta->op;

    len = strlen(fullname);
    ffield_name = calloc(len + 1, sizeof(char));
	assert(ffield_name != NULL);

    memcpy(ffield_name, fullname, len);
    aux = strtok(ffield_name, delim);
	field_name = strtok(NULL, delim);

	if (field_name == NULL)
		field_name = aux;

	list = &meta->dev_info_list;
	if (op == VM_SNAPSHOT_SAVE) {
		if (meta->snapshot_kernel) {
			buffer = &meta->buffer;
			kdata = calloc(1, data_size);
			if (kdata == NULL) {
				fprintf(stderr, "%s: Could not alloc memory at line %d\r\n",
						__func__, __LINE__);
				ret = ENOMEM;
				goto done;
			}
			fprintf(stderr, "%s: data value is %ld\r\n", __func__, *((int64_t *)buffer->buf));
			memcpy((uint8_t *) kdata, buffer->buf, data_size);

			alloc_device_info_elem(list, field_name, kdata, type, data_size);

			buffer->buf += data_size;
			buffer->buf_rem -= data_size;
			free(kdata);
		} else
			alloc_device_info_elem(list, field_name, data, type, data_size);

		if (list->auto_index >= 0)
			list->auto_index++;
	} else if (op == VM_SNAPSHOT_RESTORE) {
		/* TODO */
		aux_elem = list->first;
		if (aux_elem != NULL) {
			memcpy((uint8_t *)data, (uint8_t *)aux_elem->field_data, data_size);
			// fprintf(stderr, "%s: the expected name is %s and the actual name is %s\r\n", __func__, field_name, aux_elem->field_name);
		}
		remove_first_elem(list);
	} else {
		ret = EINVAL;
		goto done;
	}

done:
	free(ffield_name);
	return (ret);
}

int
vm_snapshot_save_fieldname_cmp(const char *fullname, volatile void *data,
				char *type, size_t data_size, struct vm_snapshot_meta *meta)
{
	size_t len;
	char *ffield_name;
	char *aux;
    char *field_name;
	int op;
	int ret;
	struct list_device_info *list;
	struct vm_snapshot_device_info *aux_elem;
    const char delim[5] = "&(>)";

	op = meta->op;

    len = strlen(fullname);
    ffield_name = calloc(len + 1, sizeof(char));
	assert(ffield_name != NULL);

    memcpy(ffield_name, fullname, len);
    aux = strtok(ffield_name, delim);
	field_name = strtok(NULL, delim);

	if (field_name == NULL)
		field_name = aux;

	list = &meta->dev_info_list;
	if (op == VM_SNAPSHOT_SAVE) {
		ret = 0;
		alloc_device_info_elem(list, field_name, data, type, data_size);
		if (list->auto_index >= 0)
			list->auto_index++;
	} else if (op == VM_SNAPSHOT_RESTORE) {
		/* TODO */
		aux_elem = list->first;
		if (aux_elem != NULL) {
			ret = memcmp((uint8_t *)data, (uint8_t *)aux_elem->field_data, data_size);
			// fprintf(stderr, "%s: the expected name is %s and the actual name is %s\r\n", __func__, field_name, aux_elem->field_name);
		}
		remove_first_elem(list);
	} else {
		ret = EINVAL;
		goto done;
	}

done:
	free(ffield_name);
	return (ret);
}

void
vm_snapshot_add_intern_list(const char *arr_name, struct vm_snapshot_meta *meta)
{
	meta->dev_info_list.intern_arr_names[meta->dev_info_list.ident++] = arr_name;
}

void
vm_snapshot_remove_intern_list(struct vm_snapshot_meta *meta)
{
	meta->dev_info_list.intern_arr_names[--meta->dev_info_list.ident] = NULL;
}

void
vm_snapshot_set_intern_arr_index(struct vm_snapshot_meta *meta, int index)
{
	meta->dev_info_list.index = index;
}

void
vm_snapshot_clear_intern_arr_index(struct vm_snapshot_meta *meta)
{
	meta->dev_info_list.index = -1;
}

void vm_snapshot_activate_auto_index(struct vm_snapshot_meta *meta,
			unsigned char create_instance)
{
	meta->dev_info_list.create_instance = create_instance;
	meta->dev_info_list.auto_index = 0;
}

void vm_snapshot_deactivate_auto_index(struct vm_snapshot_meta *meta)
{
	meta->dev_info_list.create_instance = 1;
	meta->dev_info_list.auto_index = -1;
}

void
vm_snapshot_buf_err(const char *bufname, const enum vm_snapshot_op op)
{
	const char *__op;

	if (op == VM_SNAPSHOT_SAVE)
		__op = "save";
	else if (op == VM_SNAPSHOT_RESTORE)
		__op = "restore";
	else
		__op = "unknown";

	fprintf(stderr, "%s: snapshot-%s failed for %s\r\n",
		__func__, __op, bufname);
}

int
vm_snapshot_buf(volatile void *data, size_t data_size,
		struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;
	int op;

	buffer = &meta->buffer;
	op = meta->op;

	if (buffer->buf_rem < data_size) {
		fprintf(stderr, "%s: buffer too small\r\n", __func__);
		return (E2BIG);
	}

	if (op == VM_SNAPSHOT_SAVE)
		memcpy(buffer->buf, (uint8_t *) data, data_size);
	else if (op == VM_SNAPSHOT_RESTORE)
		memcpy((uint8_t *) data, buffer->buf, data_size);
	else
		return (EINVAL);

	buffer->buf += data_size;
	buffer->buf_rem -= data_size;

	return (0);
}

size_t
vm_get_snapshot_size(struct vm_snapshot_meta *meta)
{
	size_t length;
	struct vm_snapshot_buffer *buffer;

	buffer = &meta->buffer;

	if (buffer->buf_size < buffer->buf_rem) {
		fprintf(stderr, "%s: Invalid buffer: size = %zu, rem = %zu\r\n",
			__func__, buffer->buf_size, buffer->buf_rem);
		length = 0;
	} else {
		length = buffer->buf_size - buffer->buf_rem;
	}

	return (length);
}

int
vm_snapshot_guest2host_addr_v2(void **addrp, size_t len, vm_paddr_t *gadr,
				bool restore_null, struct vm_snapshot_meta *meta)
{
	int ret = 0;
	vm_paddr_t gaddr;

	gaddr = paddr_host2guest(meta->ctx, *addrp);
	if (gaddr == (vm_paddr_t) -1) {
		if (!restore_null ||
			(restore_null && (*addrp != NULL))) {
			ret = EFAULT;
			goto done;
		}
	}
	memcpy(*addrp, &gaddr, sizeof(gaddr));

done:
	return (ret);
}

int
vm_snapshot_host2guest_addr_v2(void **addrp, size_t len, vm_paddr_t *gadr,
				bool restore_null, struct vm_snapshot_meta *meta)
{
	int ret = 0;
	vm_paddr_t gaddr;

	SNAPSHOT_VAR_OR_LEAVE(gaddr, meta, ret, done);
	if (gaddr == (vm_paddr_t) -1) {
		if (!restore_null) {
			ret = EFAULT;
			goto done;
		}
	}

	*addrp = paddr_guest2host(meta->ctx, gaddr, len);

done:
	return (ret);
}

int
vm_snapshot_guest2host_addr(void **addrp, size_t len, bool restore_null,
			    struct vm_snapshot_meta *meta)
{
	int ret;
	vm_paddr_t gaddr;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		gaddr = paddr_host2guest(meta->ctx, *addrp);
		if (gaddr == (vm_paddr_t) -1) {
			if (!restore_null ||
			    (restore_null && (*addrp != NULL))) {
				ret = EFAULT;
				goto done;
			}
		}

		SNAPSHOT_VAR_OR_LEAVE(gaddr, meta, ret, done);
	} else if (meta->op == VM_SNAPSHOT_RESTORE) {
		SNAPSHOT_VAR_OR_LEAVE(gaddr, meta, ret, done);
		if (gaddr == (vm_paddr_t) -1) {
			if (!restore_null) {
				ret = EFAULT;
				goto done;
			}
		}

		*addrp = paddr_guest2host(meta->ctx, gaddr, len);
	} else {
		ret = EINVAL;
	}

done:
	return (ret);
}

int
vm_snapshot_buf_cmp(volatile void *data, size_t data_size,
		    struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;
	int op;
	int ret;

	buffer = &meta->buffer;
	op = meta->op;

	if (buffer->buf_rem < data_size) {
		fprintf(stderr, "%s: buffer too small\r\n", __func__);
		ret = E2BIG;
		goto done;
	}

	if (op == VM_SNAPSHOT_SAVE) {
		ret = 0;
		memcpy(buffer->buf, (uint8_t *) data, data_size);
	} else if (op == VM_SNAPSHOT_RESTORE) {
		ret = memcmp((uint8_t *) data, buffer->buf, data_size);
	} else {
		ret = EINVAL;
		goto done;
	}

	buffer->buf += data_size;
	buffer->buf_rem -= data_size;

done:
	return (ret);
}
