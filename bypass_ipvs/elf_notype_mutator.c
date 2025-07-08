#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <string.h>

#include "libecbpf.h"

/*
 * POC of using libelf for manipulating symbol table entries.  Right now 
 * this implements the same functionality as xdp-progs/elfmapmod.c to 
 * change symbol types.
 */
int main(int argc, char **argv)
{
	Elf *e;
	int fd;

	if (argc != 2)
		errx(EX_USAGE, "usage: %s file", argv[0]);

	// open object file
	e = ecbpf_elf_open_filename(argv[1], &fd);
	ecbpf_elf_set_maps_notype(e);
	printf("Writing\n");
	ecbpf_elf_write_close(e, fd);
	exit(EX_OK);
}
