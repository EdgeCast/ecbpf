#ifndef _cfg_h
#define _cfg_h
#include "rules.h"
#include "test.h"

extern FILE *yyin;

struct fw_cfg* cfg_new(char *filename);
void cfg_free(struct fw_cfg *);
void cfg_print(struct fw_cfg *);
void cfg_add_rule(struct fw_cfg *config, struct rule *rule);
void cfg_add_test(struct fw_cfg *config, struct test *test);
#endif // _cfg_h
