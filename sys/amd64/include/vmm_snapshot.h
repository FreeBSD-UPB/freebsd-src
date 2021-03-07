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
 *
 * $FreeBSD$
 */

#ifndef _VMM_SNAPSHOT_
#define _VMM_SNAPSHOT_

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#endif

struct vmctx;

enum snapshot_req {
	STRUCT_VMX,
	STRUCT_VIOAPIC,
	STRUCT_VM,
	STRUCT_VLAPIC,
	VM_MEM,
	STRUCT_VHPET,
	STRUCT_VMCX,
	STRUCT_VATPIC,
	STRUCT_VATPIT,
	STRUCT_VPMTMR,
	STRUCT_VRTC,
};

struct vm_snapshot_buffer {
	/*
	 * R/O for device-specific functions;
	 * written by generic snapshot functions.
	 */
	uint8_t *const buf_start;
	const size_t buf_size;

	/*
	 * R/W for device-specific functions used to keep track of buffer
	 * current position and remaining size.
	 */
	uint8_t *buf;
	size_t buf_rem;

	/*
	 * Length of the snapshot is either determined as (buf_size - buf_rem)
	 * or (buf - buf_start) -- the second variation returns a signed value
	 * so it may not be appropriate.
	 *
	 * Use vm_get_snapshot_size(meta).
	 */
};

#ifndef JSON_SNAPSHOT_V2
#define JSON_SNAPSHOT_V2

#define JSON_V1	1
#define	JSON_V2 2

#include <sys/time.h>
#include <machine/vmm.h>

#define IDENT_LEVEL		10

/* ####################### kernel structs copies ######################### */

#define VM_MAXCPU   16          /* maximum virtual cpus */

/* vhpet */
#define VHPET_NUM_TIMERS    8

struct timer_userspace {
        uint64_t    cap_config; /* Configuration */
        uint64_t    msireg;     /* FSB interrupt routing */
        uint32_t    compval;    /* Comparator */
        uint32_t    comprate;
        sbintime_t  callout_sbt;    /* time when counter==compval */
};

struct vhpet_userspace {
    sbintime_t  freq_sbt;

    uint64_t    config;     /* Configuration */
    uint64_t    isr;        /* Interrupt Status */
    uint32_t    countbase;  /* HPET counter base value */
    sbintime_t  countbase_sbt;  /* uptime corresponding to base value */

    struct timer_userspace timer[VHPET_NUM_TIMERS];
};

/* vioapic */

#define REDIR_ENTRIES   32

struct rtbl_userspace {
    uint64_t reg;
    int acnt;   /* sum of pin asserts (+1) and deasserts (-1) */
};

struct vioapic_userspace {
    uint32_t    id;
    uint32_t    ioregsel;
    struct rtbl_userspace rtbl[REDIR_ENTRIES];
};

/* vm (vcpus) */
/*
 * Initialization:
 * (a) allocated when vcpu is created
 * (i) initialized when vcpu is created and when it is reinitialized
 * (o) initialized the first time the vcpu is created
 * (x) initialized before use
 */
struct vcpu_userspace {
    enum x2apic_state x2apic_state; /* (i) APIC mode */
    uint64_t    exitintinfo;    /* (i) events pending at VM exit */
    int exc_vector;     /* (x) exception collateral */
    int exc_errcode_valid;
    uint32_t exc_errcode;
    uint64_t    guest_xcr0; /* (i) guest %xcr0 register */
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
struct vm_userspace {
    struct vcpu_userspace vcpu[VM_MAXCPU];    /* (i) guest vcpus */
};

/* vlapic */
#define APIC_LVT_CMCI       6
#define APIC_LVT_MAX        APIC_LVT_CMCI

enum boot_state_userspace {
    BS_INIT_USERSPACE,
    BS_SIPI_USERSPACE,
    BS_RUNNING_USERSPACE
};

/*
 * 16 priority levels with at most one vector injected per level.
 */
#define ISRVEC_STK_SIZE     (16 + 1)

#define VLAPIC_MAXLVT_INDEX APIC_LVT_CMCI

struct vlapic_userspace {
    struct vm_userspace       *vm;
    int         vcpuid;
    struct LAPIC        *apic_page;

    uint32_t        esr_pending;

    struct bintime  timer_fire_bt;  /* callout expiry time */
    struct bintime  timer_freq_bt;  /* timer frequency */
    struct bintime  timer_period_bt; /* timer period */

    /*
     * The 'isrvec_stk' is a stack of vectors injected by the local apic.
     * A vector is popped from the stack when the processor does an EOI.
     * The vector on the top of the stack is used to compute the
     * Processor Priority in conjunction with the TPR.
     */
    uint8_t     isrvec_stk[ISRVEC_STK_SIZE];
    int     isrvec_stk_top;

    uint64_t    msr_apicbase;
    enum boot_state_userspace boot_state;

    /*
     * Copies of some registers in the virtual APIC page. We do this for
     * a couple of different reasons:
     * - to be able to detect what changed (e.g. svr_last)
     * - to maintain a coherent snapshot of the register (e.g. lvt_last)
     */
    uint32_t    svr_last;
    uint32_t    lvt_last[VLAPIC_MAXLVT_INDEX + 1];
};

/* vatpic */
struct atpic_userspace {
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

struct vatpic_userspace {
    struct atpic_userspace    atpic[2];
    uint8_t     elc[2];
};

/* vatpit */
struct vatpit_userspace;

struct vatpit_callout_arg_userspace {
    struct vatpit_userspace   *vatpit;
    int     channel_num;
};

struct channel_userspace {
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
    struct bintime  callout_bt; /* target time */
    struct vatpit_callout_arg_userspace callout_arg;
};

struct vatpit_userspace {
    struct bintime  freq_bt;
    struct channel_userspace  channel[3];
};

/* vmptmr */
struct vpmtmr_userspace { 
    sbintime_t  freq_sbt;
    sbintime_t  baseuptime;
    uint32_t    baseval;
};

/* vrtc */
/* Register layout of the RTC */
struct rtcdev_userspace {
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

struct vrtc_userspace {
    u_int       addr;       /* RTC register to read or write */
    sbintime_t  base_uptime;
    time_t      base_rtctime;
    struct rtcdev_userspace   rtcdev;
};

/* vmx */
#define VMCS_GUEST_IA32_SYSENTER_CS 0x0000482A
#define VMCS_GUEST_IA32_SYSENTER_ESP    0x00006824
#define VMCS_GUEST_IA32_SYSENTER_EIP    0x00006826
#define VMCS_GUEST_INTERRUPTIBILITY 0x00004824
#define VMCS_GUEST_ACTIVITY     0x00004826
#define VMCS_ENTRY_CTLS         0x00004012
#define VMCS_EXIT_CTLS          0x0000400C

struct vmxctx_userspace {
    register_t  guest_rdi;      /* Guest state */
    register_t  guest_rsi;
    register_t  guest_rdx;
    register_t  guest_rcx;
    register_t  guest_r8;
    register_t  guest_r9;
    register_t  guest_rax;
    register_t  guest_rbx;
    register_t  guest_rbp;
    register_t  guest_r10;
    register_t  guest_r11;
    register_t  guest_r12;
    register_t  guest_r13;
    register_t  guest_r14;
    register_t  guest_r15;
    register_t  guest_cr2;
    register_t  guest_dr0;
    register_t  guest_dr1;
    register_t  guest_dr2;
    register_t  guest_dr3;
    register_t  guest_dr6;

    register_t  host_r15;       /* Host state */
    register_t  host_r14;
    register_t  host_r13;
    register_t  host_r12;
    register_t  host_rbp;
    register_t  host_rsp;
    register_t  host_rbx;
    register_t  host_dr0;
    register_t  host_dr1;
    register_t  host_dr2;
    register_t  host_dr3;
    register_t  host_dr6;
    register_t  host_dr7;
    uint64_t    host_debugctl;
    int     host_tf;

    int     inst_fail_status;
};

struct vmxcap_userspace {
    int set;
    uint32_t proc_ctls;
    uint32_t proc_ctls2;
    uint32_t exc_bitmap;
};

struct vmxstate_userspace {
    uint64_t nextrip;   /* next instruction to be executed by guest */
    int lastcpu;    /* host cpu that this 'vcpu' last ran on */
    uint16_t vpid;
};

struct apic_page_userspace {
    uint32_t reg[PAGE_SIZE / 4];
};

/* Index into the 'guest_msrs[]' array */
enum {
    IDX_MSR_LSTAR_USERSPACE,
    IDX_MSR_CSTAR_USERSPACE,
    IDX_MSR_STAR_USERSPACE,
    IDX_MSR_SF_MASK_USERSPACE,
    IDX_MSR_KGSBASE_USERSPACE,
    IDX_MSR_PAT_USERSPACE,
    IDX_MSR_TSC_AUX_USERSPACE,
    GUEST_MSR_NUM_USERSPACE       /* must be the last enumeration */
};

struct vmcs_userspace {
    uint32_t    identifier;
    uint32_t    abort_code;
    char        _impl_specific[PAGE_SIZE - sizeof(uint32_t) * 2];
};

struct vmx_userspace {
    struct vmcs_userspace vmcs[VM_MAXCPU];    /* one vmcs per virtual cpu */
    struct apic_page_userspace apic_page[VM_MAXCPU];  /* one apic page per vcpu */
    char        msr_bitmap[PAGE_SIZE];
    uint64_t    guest_msrs[VM_MAXCPU][GUEST_MSR_NUM_USERSPACE];
    struct vmxctx_userspace   ctx[VM_MAXCPU];
    struct vmxcap_userspace   cap[VM_MAXCPU];
    struct vmxstate_userspace state[VM_MAXCPU];
    uint64_t    eptp;
    struct vm_userspace   *vm;
    long        eptgen[MAXCPU];     /* cached pmap->pm_eptgen */
};

/* ####################### kernel structs copies ######################### */

struct vm_snapshot_device_info {
	unsigned char ident;
	unsigned char create_instance;
	char *field_name;
	char *type;
	int index;
	char *intern_arr_name;
	void *field_data;
	size_t data_size;

	struct vm_snapshot_device_info *next_field;
};

struct list_device_info {
	unsigned char ident;
	unsigned char create_instance;
	char *type;
	const char *intern_arr_names[IDENT_LEVEL];
	int index;
	int auto_index;

	struct vm_snapshot_device_info *first;
	struct vm_snapshot_device_info *last;
};

#endif

enum vm_snapshot_op {
	VM_SNAPSHOT_SAVE,
	VM_SNAPSHOT_RESTORE,
};

struct vm_snapshot_meta {
	struct vmctx *ctx;
	void *dev_data;
	const char *dev_name;      /* identify userspace devices */
	enum snapshot_req dev_req; /* identify kernel structs */

	struct vm_snapshot_buffer buffer;

#ifdef JSON_SNAPSHOT_V2
	struct list_device_info dev_info_list;
	unsigned char snapshot_kernel;
#endif

	enum vm_snapshot_op op;
	unsigned char version;
};

int vm_snapshot_save_fieldname(const char *fullname, volatile void *data,
				char *type, size_t data_size, struct vm_snapshot_meta *meta);

void vm_snapshot_add_intern_list(const char *arr_name,
				struct vm_snapshot_meta *meta);
void vm_snapshot_remove_intern_list(struct vm_snapshot_meta *meta);

void vm_snapshot_set_intern_arr_index(struct vm_snapshot_meta *meta, int index);
void vm_snapshot_clear_intern_arr_index(struct vm_snapshot_meta *meta);

void vm_snapshot_activate_auto_index(struct vm_snapshot_meta *meta,
				unsigned char create_instance);
void vm_snapshot_deactivate_auto_index(struct vm_snapshot_meta *meta);

int vm_snapshot_save_fieldname_cmp(const char *fullname, volatile void *data,
				char *type, size_t data_size, struct vm_snapshot_meta *meta);


void vm_snapshot_buf_err(const char *bufname, const enum vm_snapshot_op op);
int vm_snapshot_buf(volatile void *data, size_t data_size,
		    struct vm_snapshot_meta *meta);
size_t vm_get_snapshot_size(struct vm_snapshot_meta *meta);

int vm_snapshot_guest2host_addr(void **addrp, size_t len, bool restore_null,
				struct vm_snapshot_meta *meta);
int vm_snapshot_buf_cmp(volatile void *data, size_t data_size,
			      struct vm_snapshot_meta *meta);

void check_and_set_non_array_type(char *type, struct vm_snapshot_meta *meta);

#ifdef JSON_SNAPSHOT_V2

#define SNAPSHOT_ADD_INTERN_ARR(ARR_NAME, META)			\
do {													\
	vm_snapshot_add_intern_list(#ARR_NAME, (META));		\
} while (0)

#define SNAPSHOT_REMOVE_INTERN_ARR(ARR_NAME, META)		\
do {													\
	vm_snapshot_remove_intern_list((META));				\
} while (0)


#define SNAPSHOT_SET_INTERN_ARR_INDEX(META, IDX)		\
do {													\
	vm_snapshot_set_intern_arr_index((META), (IDX));	\
} while (0)

#define SNAPSHOT_CLEAR_INTERN_ARR_INDEX(META)			\
do {													\
	vm_snapshot_clear_intern_arr_index((META));			\
} while (0)

/*
 * Second parameter tells if the index will be used to 
 * create a new instance or just use it with the name of 
 * the key of the element
 * 1 - create a new instance
 * 0 - do not create a new instance
 */
#define SNAPSHOT_ACTIVATE_AUTO_INDEXING(META, create_instance)		\
do {																\
	vm_snapshot_activate_auto_index((META), (create_instance));		\
} while (0)

#define SNAPSHOT_DEACTIVATE_AUTO_INDEXING(META)			\
do {													\
	vm_snapshot_deactivate_auto_index((META));			\
} while (0)

#define GET_TYPE(X) _Generic((X),		\
	/* fixed sized types */				\
	int8_t:			"int8",				\
	uint8_t:		"uint8",			\
	int16_t:		"int16",			\
	uint16_t:		"uint16",			\
	int32_t:		"int32",			\
	uint32_t:		"uint32",			\
	int64_t:		"int64",			\
	uint64_t:		"uint64",			\
	default: 		"b64"				\
)

#endif

#define	SNAPSHOT_BUF_OR_LEAVE(DATA, LEN, META, RES, LABEL)							\
do {																				\
	char *type;																		\
	type = GET_TYPE(DATA);															\
	if ((META)->version == 2) {														\
		(RES) = vm_snapshot_save_fieldname(#DATA, (DATA), type, (LEN), (META));		\
		if ((RES) != 0) {															\
			vm_snapshot_buf_err(#DATA, (META)->op);									\
			goto LABEL;																\
		}																			\
	} else {																		\
		/* TODO - Add else case */													\
		(RES) = vm_snapshot_buf((DATA), (LEN), (META));								\
		if ((RES) != 0) {															\
			vm_snapshot_buf_err(#DATA, (META)->op);									\
			goto LABEL;																\
		}																			\
	}																				\
} while (0)

#define	SNAPSHOT_VAR_OR_LEAVE(DATA, META, RES, LABEL)								\
do {																				\
		char *type;																	\
		type = GET_TYPE(DATA);														\
		check_and_set_non_array_type(type, (META));									\
		SNAPSHOT_BUF_OR_LEAVE(&(DATA), sizeof(DATA), (META), (RES), LABEL);			\
} while (0)

/*
 * Address variables are pointers to guest memory.
 *
 * When RNULL != 0, do not enforce invalid address checks; instead, make the
 * pointer NULL at restore time.
 */
#define	SNAPSHOT_GUEST2HOST_ADDR_OR_LEAVE(ADDR, LEN, RNULL, META, RES, LABEL)	\
do {																			\
	(RES) = vm_snapshot_guest2host_addr((void **)&(ADDR), (LEN),				\
					(RNULL), (META));											\
	if ((RES) != 0) {															\
		if ((RES) == EFAULT)													\
			fprintf(stderr, "%s: invalid address: %s\r\n",						\
				__func__, #ADDR);												\
		goto LABEL;																\
	}																			\
} while (0)

/* compare the value in the meta buffer with the data */
#define	SNAPSHOT_BUF_CMP_OR_LEAVE(DATA, LEN, META, RES, LABEL)						\
do {																				\
	char *type;																		\
	type = GET_TYPE(DATA);															\
	if ((META)->version == 2) {														\
		(RES) = vm_snapshot_save_fieldname_cmp(#DATA, (DATA), type, (LEN), (META));	\
		if ((RES) != 0) {															\
			vm_snapshot_buf_err(#DATA, (META)->op);									\
			goto LABEL;																\
		}																			\
	} else {																		\
		(RES) = vm_snapshot_buf_cmp((DATA), (LEN), (META));							\
		if ((RES) != 0) {															\
			vm_snapshot_buf_err(#DATA, (META)->op);									\
			goto LABEL;																\
		}																			\
	}																				\
} while (0)

#define	SNAPSHOT_VAR_CMP_OR_LEAVE(DATA, META, RES, LABEL)			\
	SNAPSHOT_BUF_CMP_OR_LEAVE(&(DATA), sizeof(DATA), (META), (RES), LABEL)

#endif
