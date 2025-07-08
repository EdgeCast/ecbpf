#include <stdio.h>
#include <err.h>
#include <sysexits.h>
#include <stdlib.h>
#include <string.h>

#include "rules.h"
#include "test.h"
#include "cfg.h"
#include "y.tab.h"

struct fw_cfg* cfg_new(char *filename) {
	int res;
	struct fw_cfg *config;

	yyin = fopen(filename, "r");

	if (yyin == NULL)
		errx(EX_USAGE, "Failed to open rules file: %m");

	config = calloc(1, sizeof(struct fw_cfg));

	res = yyparse(config);

	if (res) {
		// Free config here and return NULL in the future
		errx(EX_USAGE, "Parsing failed!");
	}

	if (config->rules_count > XDP_RULE_NUM_MAX) {
		// Free config here and return NULL in the future
		errx(EX_SOFTWARE, "Too many rules: %i is more than the maximum of %i in \"%s\".\n",
				config->rules_count, XDP_RULE_NUM_MAX, filename);
	}

	if (config->rules_count < 1) {
		errx(EX_USAGE, "There don't seem to be any rules in \"%s\".\n", filename);
	}
	config->filename = strdup(filename);

	return config;
}

void cfg_free(struct fw_cfg* config) {
	if (config==NULL)
		return;

	for (int i = 0; i < config->rules_count; i++)
		rule_free(config->rules[i]);

	struct test *cur, *next;
	for (int i = 0; i <= UCHAR_MAX; i++) {
		cur = config->tests[i];
		while (cur != NULL) {
			next = cur->next;
			test_free(cur);
			cur = next;
		}
	}

	if (config->filename)
		free(config->filename);

	free(config);
}

void cfg_add_test(struct fw_cfg *config, struct test *test) {
	unsigned char idx = test->sha1[0];
	if (config->tests[idx] != NULL) {
		test->next = config->tests[idx];
	}

	config->tests[idx] = test;
	config->tests_count++;
}

void cfg_add_rule(struct fw_cfg *config, struct rule *rule) {
	if (config->rules_count == RULES_MAX)
		errx(EX_USAGE, "Too many rules (limit is %i).", RULES_MAX);

	config->rules[config->rules_count] = rule;
	config->rules_count++;
}

/*
 * Configuration printing routines
 */
void cfg_print(struct fw_cfg *config) {
	for (int i = 0; i < config->rules_count; i++) {
		rule_print(stdout, config->rules[i]->opts);
		printf("\n");
	}

	struct test* cur;
	for (int i = 0; i <= UCHAR_MAX; i++) {
		cur = config->tests[i];
		while (cur != NULL) {
			test_print(cur);
			cur = cur->next;
		}
	}
}
