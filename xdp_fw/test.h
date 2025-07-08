#ifndef _test_h
#define _test_h

#include "libecbpf.h"
#include "xdp_fw.h"
void test(char *program, char *fules_filename, char *test_pcap_filename, char* log_filename);
struct test *test_new(unsigned char *sha1, enum xdp_action act);
void test_free(struct test *test);
char *xdp_ret_to_str(int ret);
void test_print(struct test *test);
#endif // _test_h
