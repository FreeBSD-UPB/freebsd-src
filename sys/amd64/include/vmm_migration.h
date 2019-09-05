/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
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


#ifndef	_VMM_MIGRATION_H_
#define	_VMM_MIGRATION_H_

#define VMM_PAGE_CHUNK	10

enum migration_req_type {
	VMM_GET_PAGES	= 0,
	VMM_SET_PAGES	= 1,
};

struct vmm_migration_page {
	vm_pindex_t	pindex;
	uint8_t		*page;
};

/*
 * A bhyve guest has two memory segments:
 * - lowmem segment: mapped from 0GB to 3GB (which is lowmem_limit)
 * - highmem segment: mapped starting from 4GB
 * The object that represents a segment is identified by start and end values.
 * */
struct vmm_migration_segment {
	vm_offset_t		start;
	vm_offset_t		end;
};

struct vmm_migration_pages_req {
	size_t					pages_required;
	enum migration_req_type			req_type;
	struct vmm_migration_segment		lowmem_segment;
	struct vmm_migration_segment		highmem_segment;
	struct vmm_migration_page		pages[VMM_PAGE_CHUNK];
};

#endif
