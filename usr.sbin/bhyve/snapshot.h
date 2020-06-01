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

#ifndef _BHYVE_SNAPSHOT_
#define _BHYVE_SNAPSHOT_

#include <machine/vmm_snapshot.h>
#include <libxo/xo.h>
#include <ucl.h>

#define BHYVE_RUN_DIR "/var/run/bhyve/"
#define MAX_SNAPSHOT_FILENAME PATH_MAX

struct vmctx;

struct restore_state {
	int kdata_fd;
	int vmmem_fd;

	void *kdata_map;
	size_t kdata_len;

	size_t vmmem_len;

	struct ucl_parser *meta_parser;
	ucl_object_t *meta_root_obj;
};

enum ipc_opcode {
	START_CHECKPOINT,
	START_SUSPEND,
};

struct checkpoint_op {
	unsigned int op;
	char snapshot_filename[MAX_SNAPSHOT_FILENAME];
};

struct checkpoint_thread_info {
	struct vmctx *ctx;
	int socket_fd;
};

typedef int (*vm_snapshot_dev_cb)(struct vm_snapshot_meta *, void *dev_meta);
typedef int (*vm_pause_dev_cb) (struct vmctx *, const char *dev_name, void *dev_meta);
typedef int (*vm_resume_dev_cb) (struct vmctx *, const char *dev_name, void *dev_meta);

struct vm_snapshot_dev_info {
	const char *dev_name;		/* device name */
	int was_restored;			/* flag to check if the device was previously restored*/
	vm_snapshot_dev_cb snapshot_cb;	/* callback for device snapshot */
	vm_pause_dev_cb pause_cb;	/* callback for device pause */
	vm_resume_dev_cb resume_cb;	/* callback for device resume */
};

struct vm_snapshot_kern_info {
	const char *struct_name;	/* kernel structure name*/
	enum snapshot_req req;		/* request type */
};

struct vm_snapshot_registered_devs {
	struct vm_snapshot_dev_info *dev_info;
	// for each device type, the meta should be specific
	void *meta_data;
	size_t meta_size;
	struct vm_snapshot_registered_devs *next_dev;
};

struct vm_snapshot_registered_devs *head_registered_devs;
void insert_registered_devs(struct vm_snapshot_dev_info *dev_info, void *meta_data, size_t meta_size);

void destroy_restore_state(struct restore_state *rstate);

const char *lookup_vmname(struct restore_state *rstate);
int lookup_memflags(struct restore_state *rstate);
size_t lookup_memsize(struct restore_state *rstate);
int lookup_guest_ncpus(struct restore_state *rstate);

void checkpoint_cpu_add(int vcpu);
void checkpoint_cpu_resume(int vcpu);
void checkpoint_cpu_suspend(int vcpu);

int restore_vm_mem(struct vmctx *ctx, struct restore_state *rstate);
int vm_restore_kern_structs(struct vmctx *ctx, struct restore_state *rstate);
int vm_restore_user_dev(struct vmctx *ctx, struct restore_state *rstate, void *dev_ptr,
	size_t dev_size, struct vm_snapshot_dev_info *dev_info, void *dev_meta);
int vm_restore_user_devs(struct vmctx *ctx, struct restore_state *rstate);
int vm_pause_user_devs(struct vmctx *ctx);
int vm_resume_user_devs(struct vmctx *ctx);

int get_checkpoint_msg(int conn_fd, struct vmctx *ctx);
void *checkpoint_thread(void *param);
int init_checkpoint_thread(struct vmctx *ctx);

int load_restore_file(const char *filename, struct restore_state *rstate);

#endif
