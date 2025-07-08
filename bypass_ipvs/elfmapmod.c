#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/mman.h>

/*
 * This program's purpose is merely to find the (eBPF) maps section and
 * change the type of OBJECT for those maps in the symbols section to
 * the type NOTYPE so that the iproute2 package's lib bpf code will process.
 * Later versions (than 4.18) iproute2 have a commit to permit both OBJECT
 * or NOTYPE to be specified for these maps and at that point this program
 * will no longer be needed (nor will it cause any harm if used).
 *
 * ELF objects should fit in standard program virtual space, so this
 * program merely mmaps the file into its space, performs the mods, and
 * causes them to be sync'ed out.  This is preferable to having to
 * lseek/read/write around the file to jump back and forth between sections, or
 * to read in the entire file that then needs small portions written out.
 *
 * Page faulting efficiency from mmap usage is not a concern here.
 */

static	void	usage_and_exit (char * arg0, char * lasterror);

int
main (int argc, char **argv)
{
	void	* elf_filep;
	char	* elf_fnamep;
	Elf64_Ehdr * elf_hdrp;
	int	fd;
	int	hdr_badclass64;
	int	hdr_badendian;
	int	hdr_badmagic;
	int	hdr_badshdrsize;
	int	hdr_badshstrndx;
	int	hdr_badversion;
	int	idx;
	int	maps_idx;
	int	numsyms;
	int	ret;
	Elf64_Shdr * shdrsp;
	char	* shstringsp;
	char	* symstringsp;
	struct stat statbuf;
	int	strtab_idx;
	int	symtab_idx;
	Elf64_Sym * symtabp;
	int	verbose = 0;

	/* Only optional verbose argument and mandatory file name allowed. */
	if (argc == 1 || argc > 3) {
args_error_exit: ;
		printf("\nUsage:\n\n%s [-v] <elf-file-to-modify>\n", argv[0]);
		printf("  -v - Verbose output of any map(s) modified\n\n");
		exit(EXIT_FAILURE);
	}

	if (argc == 3) {
		if (strcmp("-v", argv[1]))
			goto args_error_exit;
		verbose = 1;
		elf_fnamep = argv[2];
	} else
		elf_fnamep = argv[1];

	/* Open ELF object, determine size, and mmap it accordingly. */
	fd = open(elf_fnamep, O_RDWR);
	if (fd < 0) {
		printf("*** Unable to open file %s, error: %s ***\n"
		, elf_fnamep, strerror(errno));
		exit(EXIT_FAILURE);
	}

	ret = fstat(fd, &statbuf);
	if (ret < 0 ) {
		printf("*** Unable to stat file %s, error: %s *** \n"\
		, elf_fnamep, strerror(errno));
		close(fd);
		exit(EXIT_FAILURE);
	}

	elf_filep = mmap((void *)NULL, statbuf.st_size, PROT_READ|PROT_WRITE
	, MAP_SHARED, fd, 0);
	if (elf_filep == MAP_FAILED) {
		printf("*** Unable to mmap file %s, error: %s ***\n"
		, elf_fnamep, strerror(errno));
		close(fd);
		exit(EXIT_FAILURE);
	}

	/*
	 * Entire file is (virtually) present, so first validate that the ELF
	 * header specifies a format we have coded for.
	 */
	elf_hdrp = (Elf64_Ehdr *)elf_filep;

	hdr_badmagic = memcmp(elf_hdrp->e_ident, ELFMAG, sizeof(ELFMAG) - 1)
	? 1 : 0;
	hdr_badclass64 = (elf_hdrp->e_ident[EI_CLASS] != ELFCLASS64) ? 1 : 0;
	hdr_badendian = (elf_hdrp->e_ident[EI_DATA] != ELFDATA2LSB) ? 1 : 0;
	hdr_badversion = (elf_hdrp->e_ident[EI_VERSION] != EV_CURRENT) ? 1 : 0;
	hdr_badshdrsize = (elf_hdrp->e_shentsize != sizeof(Elf64_Shdr)) ? 1 : 0;
	hdr_badshstrndx = (elf_hdrp->e_shstrndx == SHN_UNDEF
	|| elf_hdrp->e_shstrndx >= SHN_LORESERVE) ? 1 : 0;

	if (hdr_badmagic + hdr_badclass64 + hdr_badendian + hdr_badversion
	+ hdr_badshdrsize + hdr_badshstrndx) {
		printf("*** ELF header format can not be handled, reason(s):\n"
		"%s%s%s%s%s%s\n"
		, hdr_badmagic ? " ELF magic number" : ""
		, hdr_badclass64 ? " ELF format not 64-bit" : ""
		, hdr_badendian ? " ELF format not little endian" : ""
		, hdr_badversion ? " ELF format wrong version" : ""
		, hdr_badshdrsize ? " ELF section headers wrong size" : ""
		, hdr_badshstrndx ? " ELF missing or unhandled section header "
		"strings reference" : "");
		goto exit_unmap_close;
	}

	/*
	 * Now set up to the headers/sections whose locations are predetermined
	 * so we can then find the needed sections to perform the maps object
	 * type change.
	 */
	shdrsp = (Elf64_Shdr *)(elf_filep + elf_hdrp->e_shoff);
	shstringsp = (char *)(elf_filep
	+ shdrsp[elf_hdrp->e_shstrndx].sh_offset);

	/* Find section headers: "maps", ".strtab", and ".symtab" sections. */
	maps_idx = -1;
	strtab_idx = -1;
	symtab_idx = -1;

	for (idx = 0; idx < elf_hdrp->e_shnum; idx++) {
		if (shdrsp[idx].sh_type == SHT_NOBITS)
			continue;
		if (!strcmp("maps", &shstringsp[shdrsp[idx].sh_name]))
			maps_idx = idx;
		else if (!strcmp(".strtab", &shstringsp[shdrsp[idx].sh_name]))
			strtab_idx = idx;
		else if (!strcmp(".symtab", &shstringsp[shdrsp[idx].sh_name]))
			symtab_idx = idx;
	}

	if (maps_idx == -1 || strtab_idx == -1 || symtab_idx == -1) {
		printf("*** Section(s) missing for symbol table map object "
		"updates:%s%s%s ***\n"
		, (maps_idx == -1) ? " maps" : ""
		, (strtab_idx == -1) ? " .strtab" : ""
		, (symtab_idx == -1) ? " .symtab" : "");
		goto exit_unmap_close;
	}

	/*
	 * ELF header sometimes references the symbols .strtab for section
	 * header strings and doesn't have a separate .shstrtab for section
	 * header strings.
	 */
	if (strtab_idx == elf_hdrp->e_shstrndx)
		symstringsp = shstringsp;
	else
		symstringsp = (char *)(elf_filep
		+ shdrsp[strtab_idx].sh_offset);

	/*
	 * Calculate # of symbol descriptors in the symbol table section's
	 * sh_size.  Point to start of symbol table section's array of
	 * descriptors and find the ones to update that are in the maps section
	 * number recorded above.
	 */
	numsyms = (int)(shdrsp[symtab_idx].sh_size / sizeof(Elf64_Sym));
	symtabp = (Elf64_Sym *)(elf_filep + shdrsp[symtab_idx].sh_offset);

	for (idx = 0; idx < numsyms; idx++) {
		if (symtabp[idx].st_shndx != maps_idx)
			continue;

		if (verbose) {
			printf("\n.symtab map symbol at offset: %08lx for "
			"symbol %s\n"
			" original symbol type: %d  symbol bind: %d  symbol "
			"size: %u\n"
			, shdrsp[symtab_idx].sh_offset + idx * sizeof(Elf64_Sym)
			, &symstringsp[symtabp[idx].st_name]
			, ELF64_ST_TYPE(symtabp[idx].st_info)
			, ELF64_ST_BIND(symtabp[idx].st_info)
			, (unsigned int)symtabp[idx].st_size);
		}

		if (ELF64_ST_TYPE(symtabp[idx].st_info) == STT_OBJECT) {
			if (verbose) {
				printf("    Modifying OBJECT->NOTYPE for "
				"symbol: %s\n\n"
				, &symstringsp[symtabp[idx].st_name]);
			}
			symtabp[idx].st_info
			= ELF64_ST_INFO(ELF64_ST_BIND(symtabp[idx].st_info)
			, STT_NOTYPE);
		}
	}

	/* Sync memory copy of file and wait. */
exit_unmap_close: ;
	ret =  msync(elf_filep, statbuf.st_size, MS_SYNC);
	if (ret < 0 ) {
		printf("*** Error msync'ing mmap file contents, error: %s ***\n"
		, strerror(errno));
	}

	ret = munmap(elf_filep, statbuf.st_size);
	if (ret < 0) {
		printf("*** Error doing unmap of file contents, error: %s ***\n"
		, strerror(errno));
	}

	close(fd);
}
