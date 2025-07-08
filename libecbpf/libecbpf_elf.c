#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <string.h>

#include "libecbpf.h"
#include "libecbpf_internal.h"

// Work around for old libelf in Xenial
#ifndef EM_BPF
#define EM_BPF		247	/* Linux BPF -- in-kernel virtual machine */
#endif

/** @defgroup elf_helper BPF ELF Object Helpers
 *  @{
 */

/**
 * @brief Open and return a Elf handle
 *
 * The pointer to fd is updated so that the file can later be closed.
 * The Elf struct internally contians a reference to the fd, but 
 * elf_end does not close it for us.
 *
 * @return section index on success, -1 on failure
 */
Elf *ecbpf_elf_open_filename(const char *filename, int *fd) {
	Elf *e;
	GElf_Ehdr ehdr;

	// Make sure libelf is sane
	if (elf_version(EV_CURRENT) == EV_NONE)
		ecbpf_warn("Elf library initilalization failed: %s",
			 elf_errmsg(-1));

	// Open the file
	if ((*fd = open(filename, O_RDWR, 0)) < 0) {
		ecbpf_warn("open %s failed: %m", filename);
		return NULL;
	}

	// populate Elf handle
	if ((e = elf_begin(*fd, ELF_C_RDWR, NULL)) == NULL) {
		ecbpf_warn("elf_begin() failed: %s", elf_errmsg(-1));
		return NULL;
	}

	// sanity check the object file
	if (elf_kind(e) != ELF_K_ELF) {
		ecbpf_warn("File \"%s\" is not an ELF object", filename);
		return NULL;
	}

	// Get the program header
	if (gelf_getehdr(e, &ehdr) == NULL) {
		ecbpf_warn("getehdr() failed: %s", elf_errmsg(-1));
		return NULL;
	}

	// Sanity check the type
	if (ehdr.e_machine != EM_BPF) {
		ecbpf_warn("File \"%s\" does not contain a BPF program", filename);
		return NULL;
	}

	return e;
}

/**
 * @brief Find ELF section index by type, optionally type + name
 *
 * Find an ELF section by name and type.  It is possible to skip
 * name checking by passing in an empty string for name.
 *
 * @return section index on success, -1 on failure
 */
Elf_Scn *ecbpf_elf_find_section(Elf *e, Elf64_Word type, const char *name) {

	GElf_Shdr shdr;
	Elf_Scn *scn = NULL;
	char *sec_name;
	size_t shstrndx; // string section index
	int ndx = -1;
	int name_len;

	// Length of name, which is 0 skips name checking
	name_len = strlen(name);

	// Grab the string section
	if (elf_getshdrstrndx(e, &shstrndx) != 0) {
		ecbpf_warn("Failed to find string section index: %s",
			 elf_errmsg(-1));
		return NULL;
	}

	// Search through the sections
	while ((scn = elf_nextscn(e, scn)) != NULL) {

		if (gelf_getshdr(scn, &shdr) != &shdr) {
			ecbpf_warn("getshdr() failed: %s", elf_errmsg(-1));
			return NULL;
		}

		sec_name = elf_strptr(e, shstrndx, shdr.sh_name);

		if (shdr.sh_type == type && (name_len == 0 || strcmp(sec_name, name) == 0)) {
			return scn;
		}
	}

	ecbpf_warn("Section not found");
	return NULL;
}

/**
 * @brief Apply function mutator to each symbol in the symbol table
 *
 * The pointer ctx can be used to store information used by the mutator between
 * invocations.  For an example see function ecbpf_elf_set_maps_notype.
 * If mutator returns non-zero, the walk terminates and the result is returned.
 *
 * @return -1 on setup failure, otherwise mutator result.
 */
int ecbpf_elf_mutate_symbols(Elf *e, void *ctx, int (*mutator)(GElf_Sym *sym, Elf_Data *data, int ndx, char* name, void *ctx)) {
	Elf_Scn *scn_symtab;
	Elf_Data *data;
	GElf_Sym sym;
	size_t shstrndx;
	int ndx = 0;
	int res;

	// Grab the string section
	if (elf_getshdrstrndx(e, &shstrndx) != 0) {
		ecbpf_warn("Failed to find string section index: %s",
			 elf_errmsg(-1));
		return -1;
	}

	// Find symbol table
	scn_symtab = ecbpf_elf_find_section(e, SHT_SYMTAB, "");

	if (!scn_symtab) {
		ecbpf_warn("No symbol table found");
		return -1;
	}

	// Find symbol table data section
	if ((data = elf_getdata(scn_symtab, NULL)) == 0 || data->d_size == 0) {
		ecbpf_warn("elf_getdata() failed: %s", elf_errmsg(-1));
		return -1;
	}

	while (gelf_getsym(data, ndx, &sym) != NULL) {
		res = mutator(&sym, data, ndx, elf_strptr(e, shstrndx, sym.st_name), ctx);
		if (res)
			return res;
		ndx++;
	}
	return res;
}


/**
 * @brief Internal mutator for ecbpf_elf_set_maps_notype
 *
 * @return 0 success, 1 on error
 */
static int _update_sym_no_type_mutator(GElf_Sym *sym, Elf_Data *data, int ndx, char *name, void *ctx) {
	int maps_ndx = *(int *)ctx;

	if (GELF_ST_TYPE(sym->st_info) == STT_OBJECT && sym->st_shndx == maps_ndx) {
		printf("Updating Object: %s\n", name);
		sym->st_info = GELF_ST_INFO(GELF_ST_BIND(sym->st_info), STT_NOTYPE);
		if(!gelf_update_sym(data, ndx, sym)) {
			ecbpf_warn("Failed to update symbol: %s", elf_errmsg(-1));
			return 1;
		}
	}
	return 0;
}

/**
 * @brief Update all maps to be type STT_NOTYPE
 *
 * In order to be compatible with older TC versions, we need to change
 * the type of the maps in the elf object file.  This also serves as 
 * an example for using ecbpf_elf_mutate_symbols.
 *
 * @return -1 on setup failure, otherwise mutator result.
 */
int ecbpf_elf_set_maps_notype(Elf *e) {
	Elf_Scn *scn_maps;
	int maps_ndx;

	scn_maps = ecbpf_elf_find_section(e, SHT_PROGBITS, "maps");
	if (!scn_maps) {
		ecbpf_warn("Failed to find maps section");
		return -1;
	}

	maps_ndx = elf_ndxscn(scn_maps);

  	return ecbpf_elf_mutate_symbols(e, (void *)&maps_ndx, &_update_sym_no_type_mutator);
}

/**
 * @brief Write a modified ELF object back to disk
 *
 * For reasons unknown to me, we need to mark the whole file as dirty when writing if back to disk.
 * This seems to have something to do with section order not being maintained.
 *
 *
 * @return -1 on failure, otherwise 0.
 */
int ecbpf_elf_write_close(Elf *e, int fd) {
	// For whatever reason, we need to flag the whole file as dirty otherwise we get a corrupt file
	elf_flagelf(e, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(e, ELF_C_WRITE) < 0) {
		ecbpf_warn("Failed to write ELF object file: %s", elf_errmsg(-1));
		return -1;
	}
	elf_end(e);
	close(fd);
	return 0;
}
/** @} */
