/*- * Copyright (c) 2017 Alexandru Elisei <alexandru.elisei@gmail.com>
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
 */
#include <sys/elf.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/linker.h>
#include <sys/elf_generic.h>
#include <sys/module.h>
#include <sys/errno.h>

#include <machine/vmm.h>
#include <machine/vmparam.h>
#include <bootstrap.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "boot.h"

#define gvatou(gva, addr)	((vm_offset_t)(gva) - KERNBASE + (vm_offset_t)(addr))

struct elf_file {
    Elf_Phdr 	*ph;
    Elf_Ehdr	*ehdr;
    Elf_Sym	*symtab;
    Elf_Hashelt	*hashtab;
    Elf_Hashelt	nbuckets;
    Elf_Hashelt	nchains;
    Elf_Hashelt	*buckets;
    Elf_Hashelt	*chains;
    Elf_Rel	*rel;
    size_t	relsz;
    Elf_Rela	*rela;
    size_t	relasz;
    char	*strtab;
    size_t	strsz;
    int		fd;
    caddr_t	firstpage;
    size_t	firstlen;
    int		kernel;
    uint64_t	off;
};

static uint64_t parse_image(struct preloaded_file *img, struct elf_file *ef, void *addr);
static void	image_addmetadata(struct preloaded_file *img, int type,
			size_t size, void *addr);
static int	image_addmodule(struct preloaded_file *img, char *modname, int version);
static void	parse_metadata(struct preloaded_file *img, struct elf_file *ef,
			Elf_Addr p_start, Elf_Addr p_end, void *addr);
static int	lookup_symbol(struct preloaded_file *imp, struct elf_file *ef,
			const char *name, Elf_Sym *symp, void *addr);
static struct kernel_module *image_findmodule(struct preloaded_file *img, char *modname,
			struct mod_depend *verinfo);

static int
load_elf_header(struct elf_file *ef)
{
	Elf_Ehdr  *ehdr;
	int  err;

	ehdr = ef->ehdr = (Elf_Ehdr *)ef->firstpage;
	/* Is it ELF? */
	if (!IS_ELF(*ehdr)) {
		err = EFTYPE;
		goto error;
	}
	if (ehdr->e_ident[EI_CLASS] != ELF_TARG_CLASS || /* Layout ? */
	    ehdr->e_ident[EI_DATA] != ELF_TARG_DATA ||
	    ehdr->e_ident[EI_VERSION] != EV_CURRENT || /* Version ? */
	    ehdr->e_version != EV_CURRENT ||
	    ehdr->e_machine != ELF_TARG_MACH) { /* Machine ? */
		err = EFTYPE;
		goto error;
	}

	return (0);

error:
	return (err);
}

int
parse_kernel(void *addr, struct vm_bootparams *bootparams)
{
	struct elf_file ef;
	struct preloaded_file img;
	Elf_Ehdr *ehdr;
	int err;
	size_t kernel_size;

	memset(&ef, 0, sizeof(struct elf_file));
	memset(&img, 0, sizeof(struct preloaded_file));

	ef.firstpage = (caddr_t)addr;
	err = load_elf_header(&ef);
	if (err != 0)
		goto exit;

	ehdr = ef.ehdr;
	if (ehdr->e_type != ET_EXEC) {
		printf("Image not a kernel\n");
		err = EPERM;
		goto exit;
	}
	ef.kernel = 1;

	printf("\tsizeof(Elf_Ehdr) = %lu\n", sizeof(Elf_Ehdr));
	printf("\tef->firstlen = %zd\n", ef.firstlen);
	printf("\tehdr->e_shoff = %lu\n", ehdr->e_shoff);

	img.f_addr = VM_GUEST_BASE_IPA;
	kernel_size = parse_image(&img, &ef, addr);
	if (kernel_size == 0) {
		err = EIO;
		goto exit;
	}
	img.f_size = kernel_size;

	image_addmetadata(&img, MODINFOMD_ELFHDR, sizeof(*ehdr), ehdr);

	bootparams->entry = ehdr->e_entry - KERNBASE;

	printf("\tkernel_size = %zd\n", kernel_size);
	printf("\tentry = 0x%zx\n", bootparams->entry);

exit:
	return (err);
}

static uint64_t
parse_image(struct preloaded_file *img, struct elf_file *ef, void *addr)
{
	Elf_Ehdr *ehdr;
	Elf_Phdr *phdr;
	Elf_Phdr *php;
	Elf_Shdr *shdr;
	Elf_Dyn *dp;
	Elf_Addr adp;
	Elf_Addr ctors;
	Elf_Addr ssym, esym;
	Elf_Addr p_start, p_end;
	Elf_Size size;
	Elf_Sym sym;
	vm_offset_t firstaddr, lastaddr;
	vm_offset_t shstr_addr;
	char *shstr;
	int symstrindex;
	int symtabindex;
	size_t chunk_len;
	uint64_t ret;
	int ndp;
	int i;
	unsigned int j;

	printf("\n\t\tLOADIMAGE\n\n");

	dp = NULL;
	shdr = NULL;
	ef->off = 0;
	ret = 0;

	ehdr = ef->ehdr;
	phdr = (Elf_Phdr *)(ef->firstpage + ehdr->e_phoff);

	firstaddr = lastaddr = 0;
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD)
			continue;
		if (firstaddr == 0 || firstaddr > phdr[i].p_vaddr)
		    firstaddr = phdr[i].p_vaddr;
		/* We mmap'ed the kernel, so p_memsz == p_filesz. */
		if (lastaddr == 0 || lastaddr < (phdr[i].p_vaddr + phdr[i].p_filesz))
		    lastaddr = phdr[i].p_vaddr + phdr[i].p_filesz;
	}
	lastaddr = roundup(lastaddr, sizeof(long));

	/*
	 * Get the section headers.  We need this for finding the .ctors
	 * section as well as for loading any symbols.  Both may be hard
	 * to do if reading from a .gz file as it involves seeking.  I
	 * think the rule is going to have to be that you must strip a
	 * file to remove symbols before gzipping it.
	 */
	chunk_len = ehdr->e_shnum * ehdr->e_shentsize;
	if (chunk_len == 0 || ehdr->e_shoff == 0)
		goto nosyms;
	shdr = (Elf_Shdr *)(ef->firstpage + ehdr->e_shoff);
	image_addmetadata(img, MODINFOMD_SHDR, chunk_len, shdr);

	printf("\tshdr = 0x%016lx\n", (uint64_t)shdr);
	printf("\tshdr[1].sh_type = %d\n", shdr[1].sh_type);

	/*
	 * Read the section string table and look for the .ctors section.
	 * We need to tell the kernel where it is so that it can call the
	 * ctors.
	 */
	chunk_len = shdr[ehdr->e_shstrndx].sh_size;
	if (chunk_len > 0) {
		shstr_addr = (vm_offset_t)(ef->firstpage + \
		    shdr[ehdr->e_shstrndx].sh_offset);
		shstr = malloc(chunk_len);
		memcpy(shstr, (void *)shstr_addr, chunk_len);
		for (i = 0; i < ehdr->e_shnum; i++) {
			if (strcmp(shstr + shdr[i].sh_name, ".ctors") != 0)
				continue;
			ctors = shdr[i].sh_addr;
			image_addmetadata(img, MODINFOMD_CTORS_ADDR,
					sizeof(ctors), &ctors);
			size = shdr[i].sh_size;
			image_addmetadata(img, MODINFOMD_CTORS_SIZE,
					sizeof(size), &size);
			break;
		}
		free(shstr);
	}

	/*
	 * Now load any symbols.
	 */
	symtabindex = -1;
	symstrindex = -1;
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type != SHT_SYMTAB)
			continue;
		for (j = 0; j < ehdr->e_phnum; j++) {
			if (phdr[j].p_type != PT_LOAD)
				continue;
			if (shdr[i].sh_offset >= phdr[j].p_offset &&
					(shdr[i].sh_offset + shdr[i].sh_size <=
					 phdr[j].p_offset + phdr[j].p_filesz)) {
				shdr[i].sh_offset = 0;
				shdr[i].sh_size = 0;
				break;
			}
		}
		if (shdr[i].sh_offset == 0 || shdr[i].sh_size == 0)
			continue;		/* alread loaded in a PT_LOAD above */
		/* Save it for loading below */
		symtabindex = i;
		symstrindex = shdr[i].sh_link;
	}
	if (symtabindex < 0 || symstrindex < 0)
		goto nosyms;

	printf("\tsymtabindex = %d\n", symtabindex);
	printf("\tsymstrindex = %d\n", symstrindex);
	printf("\tlastaddr = 0x%016lx\n", (uint64_t)lastaddr);

	ssym = lastaddr;
	printf("\tssym = 0x%016lx\n", (uint64_t)ssym);
	i = symtabindex;
	for (;;) {
		size = shdr[i].sh_size;
		lastaddr += sizeof(size);
		lastaddr += shdr[i].sh_size;
		lastaddr = roundup(lastaddr, sizeof(size));

		if (i == symtabindex)
			i = symstrindex;
		else if (i == symstrindex)
			break;
	}
	esym = lastaddr;
	printf("\tesym = 0x%016lx\n", (uint64_t)esym);

	image_addmetadata(img, MODINFOMD_SSYM, sizeof(ssym), &ssym);
	image_addmetadata(img, MODINFOMD_ESYM, sizeof(esym), &esym);

	printf("\n");

nosyms:
	ret = lastaddr - firstaddr;

	php = NULL;
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_DYNAMIC) {
			php = &phdr[i];
			adp = php->p_vaddr;
			image_addmetadata(img, MODINFOMD_DYNAMIC,
					sizeof(adp), &adp);
			break;
		}
	}
	if (php == NULL)
		goto out;
	ndp = php->p_filesz / sizeof(Elf_Dyn);
	if (ndp == 0)
		goto out;
	dp = malloc(php->p_filesz);
	if (dp == NULL)
		goto out;
	memcpy(dp, ef->firstpage + php->p_offset, php->p_filesz);

	ef->strsz = 0;
	for (i = 0; i < ndp; i++) {
		if (dp[i].d_tag == 0)
			break;
		switch(dp[i].d_tag) {
		case DT_HASH:
			ef->hashtab = (Elf_Hashelt *)(uintptr_t)dp[i].d_un.d_ptr;
			break;
		case DT_STRTAB:
			ef->strtab = (char *)(uintptr_t)dp[i].d_un.d_ptr;
		case DT_STRSZ:
			ef->strsz = dp[i].d_un.d_val;
			break;
		case DT_SYMTAB:
			ef->symtab = (Elf_Sym *)(uintptr_t)dp[i].d_un.d_ptr;
			break;
		case DT_REL:
			ef->rel = (Elf_Rel *)(uintptr_t)dp[i].d_un.d_ptr;
			break;
		case DT_RELSZ:
			ef->relsz = dp[i].d_un.d_val;
			break;
		case DT_RELA:
			ef->rela = (Elf_Rela *)(uintptr_t)dp[i].d_un.d_ptr;
			break;
		case DT_RELASZ:
			ef->relasz = dp[i].d_un.d_val;
			break;
		}
	}
	if (ef->hashtab == NULL || ef->symtab == NULL ||
	    ef->strtab == NULL || ef->strsz == 0)
		goto out;

	memcpy(&ef->nbuckets, (void *)gvatou(ef->hashtab, addr), sizeof(ef->nbuckets));
	memcpy(&ef->nchains, (void *)gvatou(ef->hashtab + 1, addr), sizeof(ef->nchains));
	ef->buckets = (Elf_Hashelt *)gvatou(ef->hashtab + 2, addr);
	ef->chains = ef->buckets + ef->nbuckets;

	if (lookup_symbol(img, ef, "__start_set_modmetadata_set", &sym, addr) != 0) {
		ret = 0;
		goto out;
	}
	p_start = gvatou(sym.st_value, addr);
	if (lookup_symbol(img, ef, "__stop_set_modmetadata_set", &sym, addr) != 0) {
		ret = ENOENT;
		goto out;
	}
	p_end = gvatou(sym.st_value, addr);

	parse_metadata(img, ef, p_start, p_end, addr);

out:
	if (dp != NULL)
		free(dp);
	if (shdr != NULL)
		free(shdr);
	return ret;
}

static void
image_addmetadata(struct preloaded_file *img, int type,
		size_t size, void *addr)
{
	struct file_metadata *md;

	md = malloc(sizeof(struct file_metadata) - sizeof(md->md_data) + size);
	md->md_size = size;
	md->md_type = type;
	memcpy(md->md_data, addr, size);
	md->md_next = img->f_metadata;
	img->f_metadata = md;
}

static uint64_t
elf_hash(const char *name)
{
	const unsigned char *p = (const unsigned char *)name;
	uint64_t h;
	uint64_t g;

	h = 0;
	while (*p != '\0') {
		h = (h << 4) + *p++;
		if ((g = h & 0xf0000000) != 0)
			h ^= g >> 24;
		h &= ~g;
	}

	return h;
}

static int
lookup_symbol(struct preloaded_file *imp, struct elf_file *ef,
			const char *name, Elf_Sym *symp, void *addr)
{
	Elf_Hashelt symnum;
	Elf_Sym sym;
	char *strp;
	uint64_t hash;

	hash = elf_hash(name);
	memcpy(&symnum, &ef->buckets[hash % ef->nbuckets], sizeof(symnum));

	while (symnum != STN_UNDEF) {
		if (symnum >= ef->nchains) {
			fprintf(stderr, "lookup_symbol: corrupt symbol table\n");
			return ENOENT;
		}

		memcpy(&sym, (void *)gvatou(ef->symtab + symnum, addr), sizeof(sym));
		if (sym.st_name == 0) {
			fprintf(stderr, "lookup_symbol: corrupt symbol table\n");
			return ENOENT;
		}

		strp = strdup((char *)gvatou(ef->strtab + sym.st_name, addr));
		if (strcmp(name, strp) == 0) {
			free(strp);
			if (sym.st_shndx != SHN_UNDEF ||
			    (sym.st_value != 0 &&
			    ELF_ST_TYPE(sym.st_info) == STT_FUNC)) {
				*symp = sym;
				return 0;
			}
			return ENOENT;
		}
		free(strp);
		memcpy(&symnum, &ef->chains[symnum], sizeof(symnum));
	}

	return ENOENT;
}

static void
parse_metadata(struct preloaded_file *img, struct elf_file *ef,
			Elf_Addr p_start, Elf_Addr p_end, void *addr)
{
	struct mod_metadata md;
	struct mod_version mver;
	char *s;
	int modcnt;
	Elf_Addr v, p;

	fprintf(stderr, "\n\t>> PARSE_METADATA\n\n");

	modcnt = 0;
	p = p_start;
	fprintf(stderr, "\np = 0x%016lx\n", (uint64_t)p);
	fprintf(stderr, "\nsizeof(v) = %lu\n", sizeof(v));
	while (p < p_end) {
		fprintf(stderr, "\nbefore memcpy\n");
		memcpy(&v, (void *)p, sizeof(v));
		fprintf(stderr, "\np = 0x%016lx\n", (uint64_t)v);
		memcpy(&md, (void *)gvatou(v, addr), sizeof(md));
		fprintf(stderr, "\nafter memcpy\n");
		md.md_data = (void *)(uintptr_t)md.md_data;
		p += sizeof(Elf_Addr);
		if (md.md_type == MDT_VERSION) {
			fprintf(stderr, "\ntype == MDT_VERSION\n");
			s = strdup((char *)gvatou(md.md_cval, addr));
			fprintf(stderr, "\nmd.md_data = 0x%016lx\n", (uint64_t)md.md_data);
			memcpy(&mver, (void *)gvatou(md.md_data, addr),
					sizeof(mver));
			fprintf(stderr, "\nbefore image_addmodule\n");
			image_addmodule(img, s, mver.mv_version);
			fprintf(stderr, "\nafter image_addmodule\n");
			free(s);
			modcnt++;
		}
	}

	if (modcnt == 0) {
		fprintf(stderr, "\nmodcnt = 0\n");
		image_addmodule(img, "kernel", 1);
		free(s);
	}
}

static int
image_addmodule(struct preloaded_file *img, char *modname, int version)
{
	struct kernel_module *mp;
	struct mod_depend mdepend;

	bzero(&mdepend, sizeof(mdepend));
	mdepend.md_ver_preferred = version;

	mp = image_findmodule(img, modname, &mdepend);
	if (mp)
		return (EEXIST);
	mp = malloc(sizeof(struct kernel_module));
	if (mp == NULL)
		return (ENOMEM);

	bzero(mp, sizeof(struct kernel_module));
	mp->m_name = strdup(modname);
	mp->m_version = version;
	mp->m_fp = img;
	mp->m_next = img->f_modules;
	img->f_modules = mp;

	return (0);
}

static struct kernel_module *
image_findmodule(struct preloaded_file *img, char *modname,
			struct mod_depend *verinfo)
{
    struct kernel_module *mp, *best;
    int bestver, mver;

    best = NULL;
    bestver = 0;
    for (mp = img->f_modules; mp != NULL; mp = mp->m_next) {
        if (strcmp(modname, mp->m_name) == 0) {
	    if (verinfo == NULL)
		return (mp);
	    mver = mp->m_version;
	    if (mver == verinfo->md_ver_preferred)
		return (mp);
	    if (mver >= verinfo->md_ver_minimum &&
		mver <= verinfo->md_ver_maximum &&
		mver > bestver) {
		best = mp;
		bestver = mver;
	    }
	}
    }

    return (best);
}
