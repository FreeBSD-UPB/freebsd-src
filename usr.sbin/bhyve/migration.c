/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2017-2020 Elena Mihailescu
 * Copyright (c) 2017-2020 Darius Mihai
 * Copyright (c) 2017-2020 Mihai Carabas
 * All rights reserved.
 * The migration feature was developed under sponsorships
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#include <capsicum_helpers.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <machine/vmm.h>
#ifndef WITHOUT_CAPSICUM
#include <machine/vmm_dev.h>
#endif
#include <vmmapi.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <unistd.h>

#include "migration.h"
#include "pci_emul.h"
#include "snapshot.h"

#define MB		(1024UL * 1024)
#define GB		(1024UL * MB)

#define ALLOCA_VM_SNAPSHOT_META(CTX, DEV_NAME, DEV_REQ, BUFFER, BUFFER_SIZE, OP)	\
({										\
	&(struct vm_snapshot_meta) {						\
		.ctx = CTX,							\
		.dev_name = DEV_NAME,						\
		.dev_req = DEV_REQ,						\
										\
		.buffer.buf_start = BUFFER,					\
		.buffer.buf_size = BUFFER_SIZE,					\
		.op = OP,							\
	};									\
										\
})

#ifdef BHYVE_DEBUG
#define DPRINTF(FMT, ...)							\
({										\
	fprintf(stderr, "%s: " FMT "\r\n", __func__, ##__VA_ARGS__);		\
 })
#else
#define DPRINTF(FMT, ...)
#endif

#define EPRINTF(FMT, ...)							\
({										\
	fprintf(stderr, "%s: " FMT "\r\n", __func__, ##__VA_ARGS__);		\
 })

int
receive_vm_migration(struct vmctx *ctx, char *migration_data)
{
	struct migrate_req req;
	char *hostname, *pos;
	int rc;

	memset(req.host, 0, MAX_HOSTNAME_LEN);
	hostname = strdup(migration_data);

	if ((pos = strchr(hostname, ',')) != NULL) {
		*pos = '\0';
		strlcpy(req.host, hostname, MAX_HOSTNAME_LEN);
		pos = pos + 1;

		rc = sscanf(pos, "%d", &(req.port));

		if (rc == 0) {
			EPRINTF("Could not parse the port");
			free(hostname);
			return -1;
		}
	} else {
		strlcpy(req.host, hostname, MAX_HOSTNAME_LEN);

		/* If only one variable could be read, it should be the host */
		req.port = DEFAULT_MIGRATION_PORT;
	}

	rc = vm_recv_migrate_req(ctx, req);

	free(hostname);
	return (rc);
}

static int
get_system_specs_for_migration(struct migration_system_specs *specs)
{
	int mib[2];
	size_t len_machine, len_model, len_pagesize;
	char interm[MAX_SPEC_LEN];
	int rc;
	int num;

	mib[0] = CTL_HW;
	mib[1] = HW_MACHINE;
	memset(interm, 0, MAX_SPEC_LEN);
	len_machine = sizeof(interm);

	rc = sysctl(mib, 2, interm, &len_machine, NULL, 0);
	if (rc != 0) {
		perror("Could not retrieve HW_MACHINE specs");
		return (rc);
	}
	strlcpy(specs->hw_machine, interm, MAX_SPEC_LEN);

	memset(interm, 0, MAX_SPEC_LEN);
	mib[0] = CTL_HW;
	mib[1] = HW_MODEL;
	len_model = sizeof(interm);
	rc = sysctl(mib, 2, interm, &len_model, NULL, 0);
	if (rc != 0) {
		perror("Could not retrieve HW_MODEL specs");
		return (rc);
	}
	strlcpy(specs->hw_model, interm, MAX_SPEC_LEN);

	mib[0] = CTL_HW;
	mib[1] = HW_PAGESIZE;
	len_pagesize = sizeof(num);
	rc = sysctl(mib, 2, &num, &len_pagesize, NULL, 0);
	if (rc != 0) {
		perror("Could not retrieve HW_PAGESIZE specs");
		return (rc);
	}
	specs->hw_pagesize = num;

	return (0);
}

static int
migration_transfer_data(int socket, void *msg, size_t len, enum migration_transfer_req req)
{
	uint64_t to_transfer, total_transferred;
	int64_t transferred;

	to_transfer = len;
	total_transferred = 0;

	while (to_transfer > 0) {
		switch (req) {
			case MIGRATION_SEND_REQ:
				transferred = send(socket, msg + total_transferred,
						  to_transfer, 0);
				break;
			case MIGRATION_RECV_REQ:
				transferred = recv(socket, msg + total_transferred,
						  to_transfer, 0);
				break;
			default:
				DPRINTF("Unknown transfer option");
				return (-1);
				break;
		}

		if (transferred == 0)
			break;
		if (transferred < 0) {
			perror("Error while transfering data");
			return (transferred);
		}

		to_transfer -= transferred;
		total_transferred += transferred;
	}

	return (0);
}

static int
migration_check_specs(int socket, enum migration_transfer_req req)
{
	struct migration_system_specs local_specs;
	struct migration_system_specs remote_specs;
	struct migration_system_specs transfer_specs;
	struct migration_message_type msg;
	enum migration_transfer_req rev_req;
	size_t response;
	int rc;

	if ((req != MIGRATION_SEND_REQ) && (req != MIGRATION_RECV_REQ)) {
		DPRINTF("Unknown option for migration req");
		return (-1);
	}

	if (req == MIGRATION_SEND_REQ)
		rev_req = MIGRATION_RECV_REQ;
	else
		rev_req = MIGRATION_SEND_REQ;

	rc = get_system_specs_for_migration(&local_specs);
	if (rc != 0) {
		EPRINTF("Could not retrieve local specs");
		return (rc);
	}

	if (req == MIGRATION_SEND_REQ) {
		/* Send message type to server: specs & len */
		msg.type = MESSAGE_TYPE_SPECS;
		msg.len = sizeof(local_specs);
	}

	rc = migration_transfer_data(socket, &msg, sizeof(msg), req);
	if (rc < 0) {
		DPRINTF("Could not send message type");
		return (-1);
	}

	if ((req == MIGRATION_RECV_REQ) && (msg.type != MESSAGE_TYPE_SPECS)) {
		DPRINTF(" Wrong message type received from remote");
		return (-1);
	}

	/* For the send req, we send the local specs and for the receive req
	 * we receive the remote specs.
	 */
	if (req == MIGRATION_SEND_REQ)
		transfer_specs = local_specs;

	rc = migration_transfer_data(socket, &transfer_specs, sizeof(transfer_specs), req);
	if (rc < 0) {
		DPRINTF("Could not transfer system specs");
		return (-1);
	}

	if (req == MIGRATION_RECV_REQ) {
		remote_specs = transfer_specs;

		/* Check specs */
		response = MIGRATION_SPECS_OK;
		if ((strncmp(local_specs.hw_model, remote_specs.hw_model, MAX_SPEC_LEN) != 0)
		    || (strncmp(local_specs.hw_machine, remote_specs.hw_machine, MAX_SPEC_LEN) != 0)
		    || (local_specs.hw_pagesize  != remote_specs.hw_pagesize)
		   ) {
			EPRINTF("System specification mismatch");
			DPRINTF("Local specs vs Remote Specs: \r\n"
				"\tmachine: %s vs %s\r\n"
				"\tmodel: %s vs %s\r\n"
				"\tpagesize: %zu vs %zu\r\n",
				local_specs.hw_machine,
				remote_specs.hw_machine,
				local_specs.hw_model,
				remote_specs.hw_model,
				local_specs.hw_pagesize,
				remote_specs.hw_pagesize
				);
			response = MIGRATION_SPECS_NOT_OK;
		}
	}

	/* The source will receive the result of the checkup (i.e.
	 * whether the migration is possible or the source and destination
	 * are incompatible for migration) and the destination will send the
	 * result of the checkup.
	 */
	rc = migration_transfer_data(socket, &response, sizeof(response), rev_req);
	if (rc < 0) {
		DPRINTF("Could not transfer response from server");
		return (-1);
	}

	if (response == MIGRATION_SPECS_NOT_OK)
		return (-1);

	fprintf(stdout, "%s: System specification accepted\r\n", __func__);

	return (0);

}

static int
get_migration_host_and_type(const char *hostname, unsigned char *ipv4_addr,
				unsigned char *ipv6_addr, int *type)
{
	struct addrinfo hints, *res;
	void *addr;
	int rc;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;

	rc = getaddrinfo(hostname, NULL, &hints, &res);

	if (rc != 0) {
		DPRINTF("Could not get address info");
		return (-1);
	}

	*type = res->ai_family;
	switch(res->ai_family) {
		case AF_INET:
			addr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
			inet_ntop(res->ai_family, addr, ipv4_addr, MAX_IP_LEN);
			break;
		case AF_INET6:
			addr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
			inet_ntop(res->ai_family, addr, ipv6_addr, MAX_IP_LEN);
			break;
		default:
			DPRINTF("Unknown address family.");
			return (-1);
	}

	return (0);
}

static int
migrate_check_memsize(size_t local_lowmem_size, size_t local_highmem_size,
		      size_t remote_lowmem_size, size_t remote_highmem_size)
{
	int ret;

	ret = MIGRATION_SPECS_OK;

	if (local_lowmem_size != remote_lowmem_size){
		ret = MIGRATION_SPECS_NOT_OK;
		DPRINTF("Local and remote lowmem size mismatch");
	}

	if (local_highmem_size != remote_highmem_size){
		ret = MIGRATION_SPECS_NOT_OK;
		DPRINTF("Local and remote highmem size mismatch");
	}

	return (ret);
}

static int
migrate_recv_memory(struct vmctx *ctx, int socket)
{
	size_t local_lowmem_size, local_highmem_size;
	size_t remote_lowmem_size, remote_highmem_size;
	char *baseaddr;
	int memsize_ok;
	int rc;

	local_lowmem_size = local_highmem_size = 0;
	remote_lowmem_size = remote_highmem_size = 0;
	rc = 0;

	rc = vm_get_guestmem_from_ctx(ctx,
			&baseaddr, &local_lowmem_size,
			&local_highmem_size);
	if (rc != 0) {
		DPRINTF("Could not get guest lowmem size and highmem size");
		return (rc);
	}

	rc = migration_transfer_data(socket, &remote_lowmem_size, sizeof(remote_lowmem_size), MIGRATION_RECV_REQ);
	if (rc < 0) {
		DPRINTF("Could not recv lowmem size");
		return (rc);
	}

	rc = migration_transfer_data(socket, &remote_highmem_size, sizeof(remote_highmem_size), MIGRATION_RECV_REQ);
	if (rc < 0) {
		DPRINTF("Could not recv highmem size");
		return (rc);
	}

	memsize_ok = migrate_check_memsize(local_lowmem_size, local_highmem_size,
					remote_lowmem_size, remote_highmem_size);

	rc = migration_transfer_data(socket,
			&memsize_ok, sizeof(memsize_ok), MIGRATION_SEND_REQ);
	if (rc < 0) {
		DPRINTF("Could not send migration_ok to remote");
		return (rc);
	}

	if (memsize_ok != MIGRATION_SPECS_OK) {
		DPRINTF("Memory size mismatch with remote host");
		return (-1);
	}

	rc = migration_transfer_data(socket, baseaddr, local_lowmem_size, MIGRATION_RECV_REQ);
	if (rc < 0) {
		DPRINTF("Could not recv chunk lowmem.");
		return (-1);
	}

	if (local_highmem_size > 0){
		rc = migration_transfer_data(socket, baseaddr + 4 * GB, local_highmem_size, MIGRATION_RECV_REQ);
		if (rc < 0) {
			DPRINTF("Could not recv highmem");
			return (-1);
		}
	}

	return (0);
}

static int
migrate_send_memory(struct vmctx *ctx, int socket)
{
	size_t lowmem_size, highmem_size;
	char *mmap_vm_lowmem, *mmap_vm_highmem;
	char *baseaddr;
	int memsize_ok;
	int rc;

	rc = 0;
	mmap_vm_lowmem = MAP_FAILED;
	mmap_vm_highmem = MAP_FAILED;

	rc = vm_get_guestmem_from_ctx(ctx, &baseaddr,
			&lowmem_size, &highmem_size);
	if (rc != 0) {
		DPRINTF("Could not get guest lowmem size and highmem size");
		return (rc);
	}

	/* Send the size of the lowmem segment */
	rc = migration_transfer_data(socket, &lowmem_size, sizeof(lowmem_size), MIGRATION_SEND_REQ);
	if (rc < 0) {
		DPRINTF("Could not send lowmem size");
		return (rc);
	}

	/* Send the size of the highmem segment */
	rc = migration_transfer_data(socket, &highmem_size, sizeof(lowmem_size), MIGRATION_SEND_REQ);
	if (rc < 0) {
		DPRINTF("Could not send highmem size");
		return (rc);
	}

	/* Wait for answer - params ok (if memory size matches) */
	rc = migration_transfer_data(socket, &memsize_ok, sizeof(memsize_ok), MIGRATION_RECV_REQ);
	if (rc < 0) {
		DPRINTF("Could not receive response from remote");
		return (rc);
	}

	if (memsize_ok != MIGRATION_SPECS_OK) {
		DPRINTF("Memory size mismatch with remote host");
		return (-1);
	}

	mmap_vm_lowmem = baseaddr;
	mmap_vm_highmem = baseaddr + 4 * GB;

	/* Send the lowmem segment */
	rc = migration_transfer_data(socket, mmap_vm_lowmem, lowmem_size, MIGRATION_SEND_REQ);
	if (rc < 0) {
		DPRINTF("Could not send lowmem");
		return (-1);
	}

	/* Send the highmem segment */
	if (highmem_size > 0){
		rc = migration_transfer_data(socket, mmap_vm_highmem, highmem_size, MIGRATION_SEND_REQ);
		if (rc < 0) {
			DPRINTF("Could not send highmem");
			return (-1);
		}
	}

	return (0);
}

/**
 * The source host saves the state for the kernel structure that will be
 * migrated and sends to the destination host a message that contains
 * the type of data to be sent (MESSAGE_TYPE_KERN), the size of the structure
 * to be received and the index that represents the kernel structure in order to
 * be identified by the destination host. Then, the source host transfer the
 * state of the kernel structure over the network and the destination host
 * restores it.
 */
static inline int
migrate_kern_struct(struct vmctx *ctx, int socket, char *buffer,
		    enum snapshot_req struct_req, enum migration_transfer_req req)
{
	int rc;
	struct migration_message_type msg;
	struct vm_snapshot_meta *meta;

	if ((req != MIGRATION_SEND_REQ) && (req != MIGRATION_RECV_REQ)) {
		DPRINTF("Unknown request");
		return (-1);
	}

	memset(&msg, 0, sizeof(msg));
	if (req == MIGRATION_SEND_REQ) {
		msg.type = MESSAGE_TYPE_KERN;

		meta = ALLOCA_VM_SNAPSHOT_META(ctx, NULL, struct_req, buffer, SNAPSHOT_BUFFER_SIZE, VM_SNAPSHOT_SAVE);
		memset(meta->buffer.buf_start, 0, meta->buffer.buf_size);
		meta->buffer.buf = meta->buffer.buf_start;
		meta->buffer.buf_rem = meta->buffer.buf_size;

		rc = vm_snapshot_req(meta);
		if (rc < 0) {
			DPRINTF("Could not get struct with req %d", struct_req);
			return (-1);
		}

		msg.len = vm_get_snapshot_size(meta);
		msg.req_type = struct_req;

	}

	rc = migration_transfer_data(socket, &msg, sizeof(msg), req);
	if (rc < 0) {
		DPRINTF("Could not transfer message type for kern struct %d", struct_req);
		return (-1);
	}

	if ((req == MIGRATION_RECV_REQ) && (msg.type != MESSAGE_TYPE_KERN)) {
		DPRINTF("Receive wrong message type.");
		return (-1);
	}

	rc = migration_transfer_data(socket, buffer, msg.len, req);
	if (rc < 0) {
		DPRINTF("Could not transfer struct with req %d", struct_req);
		return (-1);
	}

	if (req == MIGRATION_RECV_REQ) {
		meta = ALLOCA_VM_SNAPSHOT_META(ctx, NULL,  msg.req_type, buffer,
					  msg.len, VM_SNAPSHOT_RESTORE);
		meta->buffer.buf = meta->buffer.buf_start;
		meta->buffer.buf_rem = meta->buffer.buf_size;

		rc = vm_snapshot_req(meta);
		if (rc != 0) {
			DPRINTF("Failed to restore struct %d", msg.req_type);
			return (-1);
		}
	}

	return (0);
}

static int
migrate_kern_data(struct vmctx *ctx, int socket, enum migration_transfer_req req)
{
	int i, rc, error;
	int ndevs;
	char *buffer;
	const struct vm_snapshot_kern_info *snapshot_kern_structs;

	error = 0;
	snapshot_kern_structs = get_snapshot_kern_structs(&ndevs);

	buffer = malloc(SNAPSHOT_BUFFER_SIZE);
	if (buffer == NULL) {
		EPRINTF("Could not allocate memory.");
		return (-1);
	}

	for (i = 0; i < ndevs; i++) {
		if (req == MIGRATION_RECV_REQ) {
			rc = migrate_kern_struct(ctx, socket, buffer, NO_KERN_STRUCT,  MIGRATION_RECV_REQ);
			if (rc < 0) {
				DPRINTF("Could not restore struct %s", snapshot_kern_structs[i].struct_name);
				error = -1;
				break;
			}
		} else if (req == MIGRATION_SEND_REQ) {
			rc = migrate_kern_struct(ctx, socket, buffer,
					snapshot_kern_structs[i].req, MIGRATION_SEND_REQ);
			if (rc < 0) {
				DPRINTF("Could not send %s", snapshot_kern_structs[i].struct_name);
				error = -1;
				break;
			}
		} else {
			DPRINTF("Unknown transfer request");
			error = -1;
			break;
		}
	}

	free(buffer);

	return (error);
}

static inline const struct vm_snapshot_dev_info *
find_entry_for_dev(const char *name)
{
	int i;
	int ndevs;
	const struct vm_snapshot_dev_info *snapshot_devs;

	snapshot_devs = get_snapshot_devs(&ndevs);

	for (i = 0; i < ndevs; i++) {
		if (strncmp(name, snapshot_devs[i].dev_name, MAX_DEV_NAME_LEN) == 0) {
			return (&snapshot_devs[i]);
		}
	}

	return NULL;
}

static inline int
migrate_transfer_dev(struct vmctx *ctx, int socket, const char *dev,
		     char *buffer, size_t len, enum migration_transfer_req req)
{
	int rc;
	size_t data_size;
	struct migration_message_type msg;
	struct vm_snapshot_meta *meta;
	const struct vm_snapshot_dev_info *dev_info;

	if ((req != MIGRATION_SEND_REQ) && (req != MIGRATION_RECV_REQ)) {
		DPRINTF("Unknown transfer request option");
		return (-1);
	}

	memset(&msg, 0, sizeof(msg));
	memset(buffer, 0, len);
	if (req == MIGRATION_SEND_REQ) {
		dev_info = find_entry_for_dev(dev);
		if (dev_info == NULL) {
			EPRINTF("Could not find the device %s "
				"or migration not implemented yet for it.", dev);
			return (0);
		}

		meta = ALLOCA_VM_SNAPSHOT_META(ctx, dev, 0, buffer, len, VM_SNAPSHOT_SAVE);

		memset(meta->buffer.buf_start, 0, meta->buffer.buf_size);
		meta->buffer.buf = meta->buffer.buf_start;
		meta->buffer.buf_rem = meta->buffer.buf_size;

		rc = (*dev_info->snapshot_cb)(meta);
		if (rc < 0) {
			DPRINTF("Could not get info about %s dev", dev);
			return (-1);
		}

		data_size = vm_get_snapshot_size(meta);

		msg.type = MESSAGE_TYPE_DEV;
		msg.len = data_size;
		strlcpy(msg.name, dev, MAX_DEV_NAME_LEN);
	}

	rc = migration_transfer_data(socket, &msg, sizeof(msg), req);
	if (rc < 0) {
		DPRINTF("Could not transfer msg for %s dev", dev);
		return (-1);
	}

	if (req == MIGRATION_RECV_REQ) {
		if (msg.type != MESSAGE_TYPE_DEV) {
			DPRINTF("Wrong message type for device.");
			return (-1);
		}

		data_size = msg.len;
	}

	if (data_size == 0)
		return (0); // this type of device is not used


	rc = migration_transfer_data(socket, buffer, data_size, req);
	if (rc < 0) {
		DPRINTF("Could not transfer %s dev", dev);
		return (-1);
	}

	if (req == MIGRATION_RECV_REQ) {
		dev_info = find_entry_for_dev(msg.name);
		if (dev_info == NULL) {
			EPRINTF("Could not find the device %s "
				"or migration not implemented yet for it.", msg.name);
			return (0);
		}
		meta = ALLOCA_VM_SNAPSHOT_META(ctx, msg.name, 0, buffer, data_size, VM_SNAPSHOT_RESTORE);
		meta->buffer.buf = meta->buffer.buf_start;
		meta->buffer.buf_rem = meta->buffer.buf_size;

		rc = (*dev_info->snapshot_cb)(meta);
		if (rc != 0) {
			EPRINTF("Could not restore %s dev", msg.name);
			return (-1);
		}
	}

	return (0);
}

static int
migrate_devs(struct vmctx *ctx, int socket, enum migration_transfer_req req)
{
	int i, num_items;
	int rc, error;
	char *buffer;
	const struct vm_snapshot_dev_info *snapshot_devs;

	error = 0;
	buffer = malloc(SNAPSHOT_BUFFER_SIZE);
	if (buffer == NULL) {
		EPRINTF("Could not allocate memory");
		error = -1;
		goto end;
	}

	if (req == MIGRATION_SEND_REQ) {
		/*
		 * Send to the destination the number of devices that will
		 * be migrated.
		 */
		snapshot_devs = get_snapshot_devs(&num_items);

		rc = migration_transfer_data(socket, &num_items, sizeof(num_items), req);
		if (rc < 0) {
			DPRINTF("Could not send num_items to destination");
			return (-1);
		}

		for (i = 0; i < num_items; i++) {
			rc = migrate_transfer_dev(ctx, socket, snapshot_devs[i].dev_name,
						buffer, SNAPSHOT_BUFFER_SIZE, req);

			if (rc < 0) {
				DPRINTF("Could not send %s", snapshot_devs[i].dev_name);
				error = -1;
				goto end;
			}
	    }
	} else if (req == MIGRATION_RECV_REQ) {
		/* receive the number of devices that will be migrated */
		rc = migration_transfer_data(socket, &num_items, sizeof(num_items), MIGRATION_RECV_REQ);
		if (rc < 0) {
		    DPRINTF("Could not recv num_items from source");
		    return (-1);
		}

		for (i = 0; i < num_items; i++) {
			rc = migrate_transfer_dev(ctx, socket, NULL, buffer, SNAPSHOT_BUFFER_SIZE, req);
			if (rc < 0) {
				DPRINTF("Could not recv device");
				error = -1;
				goto end;
			}
		}
	}

end:
	if (buffer != NULL)
		free(buffer);

	return (error);
}

static inline int
migrate_connections(struct migrate_req req, int *socket_fd,
		    int *connection_socket_fd,
		    enum migration_transfer_req type)
{
	unsigned char ipv4_addr[MAX_IP_LEN];
	unsigned char ipv6_addr[MAX_IP_LEN];
	int addr_type;
	int error;
	int s, con_socket;
	struct sockaddr_in sa, client_sa;
	socklen_t client_len;
	int rc;

	rc = get_migration_host_and_type(req.host, ipv4_addr,
					 ipv6_addr, &addr_type);

	if (rc != 0) {
		EPRINTF("Invalid address.");
		DPRINTF("IP address used for migration: %s;\r\n"
				"Port used for migration: %d",
				req.host, req.port);
		return (rc);
	}

	if (addr_type == AF_INET6) {
		EPRINTF("IPv6 is not supported yet for migration. "
				"Please try again using a IPv4 address.");

		DPRINTF("IP address used for migration: %s;\r\nPort used for migration: %d",
			ipv6_addr, req.port);
		return (-1);
	}

	s = socket(AF_INET, SOCK_STREAM, 0);

	if (s < 0) {
		perror("Could not create socket");
		return (-1);
	}

	bzero(&sa, sizeof(sa));

	switch (type) {
		case MIGRATION_SEND_REQ:
			fprintf(stdout, "%s: Starting connection to %s on %d port...\r\n",
				__func__, ipv4_addr, req.port);

			sa.sin_family = AF_INET;
			sa.sin_port = htons(req.port);

			rc = inet_pton(AF_INET, ipv4_addr, &sa.sin_addr);
			if (rc <= 0) {
				DPRINTF("Could not retrive the IPV4 address");
				return (-1);
			}

			rc = connect(s, (struct sockaddr *)&sa, sizeof(sa));

			if (rc < 0) {
				perror("Could not connect to the remote host");
				error = rc;
				goto done_close_s;
			}
			*socket_fd = s;
			break;
		case MIGRATION_RECV_REQ:
			fprintf(stdout, "%s: Waiting for connections from %s on %d port...\r\n",
					__func__, ipv4_addr, req.port);

			sa.sin_family = AF_INET;
			sa.sin_port = htons(req.port);
			sa.sin_addr.s_addr = htonl(INADDR_ANY);

			rc = bind(s, (struct sockaddr *)&sa, sizeof(sa));

			if (rc < 0) {
				perror("Could not bind");
				error = rc;
				goto done_close_s;
			}

			listen(s, 1);

			con_socket = accept(s, (struct sockaddr *)&client_sa, &client_len);
			if (con_socket < 0) {
				EPRINTF("Could not accept connection");
				error = -1;
				goto done_close_s;
			}
			*socket_fd = s;
			*connection_socket_fd = con_socket;
			break;
		default:
			EPRINTF("unknown operation request");
			error = -1;
			goto done;
	}

	error = 0;
	goto done;

done_close_s:
	close(s);
done:
	return (error);
}

int
vm_send_migrate_req(struct vmctx *ctx, struct migrate_req req)
{
	int s;
	int rc, error;
	size_t migration_completed;

	rc = migrate_connections(req, &s, NULL, MIGRATION_SEND_REQ);
	if (rc < 0) {
		EPRINTF("Could not create connection");
		return (-1);
	}

	rc = migration_check_specs(s, MIGRATION_SEND_REQ);

	if (rc < 0) {
		EPRINTF("Error while checking system requirements");
		error = rc;
		goto done;
	}

	vm_vcpu_pause(ctx);

	rc = vm_pause_user_devs(ctx);
	if (rc != 0) {
		EPRINTF("Could not pause devices");
		error = rc;
		goto unlock_vm_and_exit;
	}

	rc = migrate_send_memory(ctx, s);
	if (rc != 0) {
		EPRINTF("Could not send memory to destination");
		error = rc;
		goto unlock_vm_and_exit;
	}

	rc =  migrate_kern_data(ctx, s, MIGRATION_SEND_REQ);
	if (rc != 0) {
		EPRINTF("Could not send kern data to destination");
		error = rc;
		goto unlock_vm_and_exit;
	}

	rc =  migrate_devs(ctx, s, MIGRATION_SEND_REQ);
	if (rc < 0) {
		EPRINTF("Could not send pci devs to destination");
		error = rc;
		goto unlock_vm_and_exit;
	}

	rc = migration_transfer_data(s, &migration_completed,
					sizeof(migration_completed), MIGRATION_RECV_REQ);
	if ((rc < 0) || (migration_completed != MIGRATION_SPECS_OK)) {
		EPRINTF("Could not recv migration completed remote or received error");
		error = -1;
		goto unlock_vm_and_exit;
	}

	vm_destroy(ctx);
	exit(0);

unlock_vm_and_exit:
	vm_vcpu_resume(ctx);

	rc = vm_resume_user_devs(ctx);
	if (rc != 0)
		EPRINTF("Could not resume devices");
done:
	close(s);
	return (error);
}

int
vm_recv_migrate_req(struct vmctx *ctx, struct migrate_req req)
{
	int s, con_socket;
	int rc;
	size_t migration_completed;

	rc = migrate_connections(req, &s, &con_socket, MIGRATION_RECV_REQ);
	if (rc != 0) {
		EPRINTF("Could not create connections");
		return (-1);
	}

	rc = migration_check_specs(con_socket, MIGRATION_RECV_REQ);
	if (rc < 0) {
		EPRINTF("Error while checking specs");
		close(con_socket);
		close(s);
		return (rc);
	}

	rc = migrate_recv_memory(ctx, con_socket);
	if (rc < 0) {
		EPRINTF("Could not recv :lowmem and highmem");
		close(con_socket);
		close(s);
		return (-1);
	}

	rc = migrate_kern_data(ctx, con_socket, MIGRATION_RECV_REQ);
	if (rc < 0) {
		EPRINTF("Could not recv kern data");
		close(con_socket);
		close(s);
		return (-1);
	}

	rc = migrate_devs(ctx, con_socket, MIGRATION_RECV_REQ);
	if (rc < 0) {
		EPRINTF("Could not recv pci devs");
		close(con_socket);
		close(s);
		return (-1);
	}

	fprintf(stdout, "%s: Migration completed\r\n", __func__);
	migration_completed = MIGRATION_SPECS_OK;
	rc = migration_transfer_data(con_socket, &migration_completed,
					sizeof(migration_completed), MIGRATION_SEND_REQ);
	if (rc < 0) {
		EPRINTF("Could not send migration completed remote");
		close(con_socket);
		close(s);
		return (-1);
	}

	close(con_socket);
	close(s);
	return (0);
}

