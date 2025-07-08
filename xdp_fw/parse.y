%{
	#include <stdio.h>
	#include <err.h>
	#include <sysexits.h>
	#include <stdlib.h>
	#include <string.h>
	#include <arpa/inet.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netdb.h>

	#include "rules.h"
	#include "test.h"
	#include "cfg.h"

	#define DEBUG 1
	#define pr_debug(...) do { \
		if (DEBUG) fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
		} while(0); 

	#define CWR (1<<7)
	#define ECE (1<<6)
	#define URG (1<<5)
	#define ACK (1<<4)
	#define PSH (1<<3)
	#define RST (1<<2)
	#define SYN (1<<1)
	#define FIN (1<<0)

	#include "y.tab.h"
	int yylex( YYSTYPE *lvalp, YYLTYPE *llocp);

	void yyerror(YYLTYPE *, struct fw_cfg *config, const char *, ...);

	int validate_ip(int family, struct fw_ip *ip, YYLTYPE *, struct fw_cfg *config);
	int ip_has_family(int family, struct fw_ip *ip);

	// protos for repeated callocs
	struct fw_packet_opts *mk_fw_packet_opts(int length);
	struct fw_meta_opts *mk_fw_meta_opts(char *name);


	// globals
	struct {
		uint8_t flags;
		uint8_t mask;
	} flags;
	uint8_t flag_set;

%}

%require "3.0"
%define parse.lac full
%define parse.error verbose
%define api.pure full
%locations
%parse-param {struct fw_cfg *config}

%union
{
	int number;
	uint8_t uint8;
	unsigned char sha1[SHA1_SIZE];
	enum xdp_action act;
	char* string;
	struct rule *rule;
	struct test *test;
	struct fw_packet_opts *fw_packet_opts;
	struct fw_opts *fw_opts;
	struct fw_ip *fw_ip;
	struct fw_ip_opts *fw_ip_opts;
	struct fw_tcp_opts *fw_tcp_opts;
	struct fw_udp_opts *fw_udp_opts;
	struct fw_icmp_opts *fw_icmp_opts;
	struct fw_meta_opts *fw_meta_opts;
	struct fw_port *fw_port;
}

%token EOL
%token NAME_KW
%token PACKET_KW "`packet`" LENGTH_KW "`length`"
%token IP_KW "`ip`" IP6_KW "ip6" TTL_KW "ttl" TO_KW "`to`" FROM_KW "`from`" ANY_KW "`any`"
%token TCP_KW "`tcp`" WINDOW_KW "`window`" FLAGS_KW "`flags`" MASK_KW "`mask`"
%token CWR_KW "`cwr`" ECE_KW "`ece`" URG_KW "`urg`" ACK_KW "`ack`" PSH_KW "`psh`" RST_KW "`rst`" SYN_KW "`syn`" FIN_KW "`fin`"
%token ICMP_KW "`icmp`" ICMP6_KW "`icmp6`" TYPE_KW "`type`"
%token UDP_KW "`udp`" SPORT_KW "`sport`"
%token TEST_KW "`test`" SHA1_KW "a sha1 sum" XDP_ACTION_KW "(`XDP_PASS`, `XDP_DROP`, `XDP_ABORTED`)"
%token <sha1> SHA1 
%token <act> XDP_ACTION
%token <number> NUMBER
%token <string> IP QUOTED_STRING

%nterm <rule> rule
%nterm <fw_opts> fw_opt_list fw_opt
%nterm <fw_packet_opts> fw_packet_opts
%nterm <number> fw_packet_length
%nterm <fw_ip> fw_ip fw_ip_list fw_ip_spec
%nterm <fw_ip_opts> fw_ip_opts
%nterm <number> fw_ip_ttl fw_ip_family fw_icmp_type
%nterm <fw_tcp_opts> fw_tcp_opts
%nterm <number> fw_tcp_window 
%nterm <fw_port> fw_sport fw_port_spec fw_port_list fw_port
%nterm <fw_udp_opts> fw_udp_opts
%nterm <fw_icmp_opts> fw_icmp_opts
%nterm <fw_meta_opts> fw_meta_opts
%nterm <test> test
%nterm <uint8> tcp_flags;

%%
rules: %empty
 | rules rule EOL { cfg_add_rule(config, $2); }
 | rules test EOL { cfg_add_test(config, $2); }
 | rules EOL { }
;

test: TEST_KW SHA1_KW SHA1 XDP_ACTION_KW XDP_ACTION { $$ = test_new($SHA1, $XDP_ACTION); }

rule: fw_opt_list {
	// Shim in the old creation logic
	struct fw_opts *cur = $fw_opt_list;

	struct fw_packet_opts *fw_packet_opts = NULL;
	struct fw_ip_opts *fw_ip_opts = NULL;
	struct fw_tcp_opts *fw_tcp_opts = NULL;
	struct fw_udp_opts *fw_udp_opts = NULL;
	struct fw_icmp_opts *fw_icmp_opts = NULL;
	struct fw_meta_opts *fw_meta_opts = NULL;

	// Validate the input and plumb in helpers
	while (cur != NULL) {
		switch (cur->opt_type) {
			case FW_OPT_PACKET:
				if (fw_packet_opts) {
					yyerror(&@fw_opt_list, config, "Multiple packet options not supported.\n");
					YYERROR;
				}
				fw_packet_opts = (struct fw_packet_opts*) cur;
				break;
			case FW_OPT_IP:
				if (fw_ip_opts) {
					yyerror(&@fw_opt_list, config, "Multiple {ip,ip6} options not supported.\n");
					YYERROR;
				}
				fw_ip_opts = (struct fw_ip_opts*) cur;
				break;
			case FW_OPT_TCP:
				if (fw_tcp_opts) {
					yyerror(&@fw_opt_list, config, "Multiple tcp options not supported.\n");
					YYERROR;
				}
				fw_tcp_opts = (struct fw_tcp_opts*) cur;
				break;
			case FW_OPT_UDP:
				if (fw_udp_opts) {
					yyerror(&@fw_opt_list, config, "Multiple udp options not supported.\n");
					YYERROR;
				}
				fw_udp_opts = (struct fw_udp_opts*) cur;
				break;
			case FW_OPT_ICMP:
				if (fw_icmp_opts) {
					yyerror(&@fw_opt_list, config, "Multiple {icmp,icmp6} options not supported.\n");
					YYERROR;
				}
				fw_icmp_opts = (struct fw_icmp_opts*) cur;
				break;
			case FW_OPT_META:
				if (fw_meta_opts) {
					yyerror(&@fw_opt_list, config, "Multiple name options not supported.\n");
					YYERROR;
				}
				fw_meta_opts = (struct fw_meta_opts*) cur;
				break;
			default:
				yyerror(&@fw_opt_list, config, "Unknown option.  Internal error.\n");
				YYERROR;
				break;
		}
		cur = cur->next;
	}

	// Make sure there is some sort of ip spec
	if (!fw_ip_opts) {
		yyerror(&@fw_opt_list, config, "Rules require one of {ip, ip6}.\n");
		YYERROR;
	}

	// Make sure a protocol is specified
	if (!fw_icmp_opts && !fw_udp_opts && !fw_tcp_opts) {
		yyerror(&@fw_opt_list, config, "Rules require one of {tcp, udp, icmp, icmp6}.\n");
		YYERROR;
	}
		
	// Make sure we don't confuse icmp6/icmp
	if (fw_icmp_opts) {
		if (fw_icmp_opts->family != fw_ip_opts->family) {
			yyerror(&@fw_opt_list, config, "Address family mismatch between source and icmp.  Family ip requires icmp and ip6 requires icmp6.\n");
			YYERROR;
		}
	}

	// Implicit option: Make sure we have a length option
	if (!fw_packet_opts) {
		fw_packet_opts = mk_fw_packet_opts(-1);
		fw_packet_opts->next = $fw_opt_list;
		$fw_opt_list = (struct fw_opts *)fw_packet_opts;
	}

	// Implicit option: Plumb in a metadata option if not specified
	if (!fw_meta_opts) {
		cur = $fw_opt_list;
		while (cur->next != NULL)
			cur = cur->next;

		fw_meta_opts =  mk_fw_meta_opts(NULL); // Set a default name
		cur->next = (struct fw_opts *) fw_meta_opts;
	}

	// Make sure to update the meta data with the rule string
	fw_meta_opts->rule = rule_to_str($fw_opt_list);

	$$ = rule_new($fw_opt_list);
};

fw_opt_list: fw_opt_list fw_opt { $$->tail->next = $fw_opt; $$->tail = $fw_opt; }
         | fw_opt { $$ = $fw_opt; }
;

fw_opt: fw_packet_opts { $$ = (struct fw_opts *) $fw_packet_opts; }
	| fw_ip_opts { $$ = (struct fw_opts *) $fw_ip_opts; }
	| fw_tcp_opts { $$ = (struct fw_opts *) $fw_tcp_opts; }
	| fw_udp_opts { $$ = (struct fw_opts *) $fw_udp_opts; }
	| fw_icmp_opts { $$ = (struct fw_opts *) $fw_icmp_opts; }
	| fw_meta_opts { $$ = (struct fw_opts *) $fw_meta_opts; }

/*
 * Name Options
 */
fw_meta_opts: NAME_KW QUOTED_STRING {
	$$ = mk_fw_meta_opts($QUOTED_STRING);
} 
;


/*
 * Packet Options
 */
fw_packet_opts: PACKET_KW fw_packet_length {
	$$ = mk_fw_packet_opts($fw_packet_length);
	}
;

fw_packet_length: %empty { $$ = -1; }
		| LENGTH_KW ANY_KW { $$ = -1; }
		| LENGTH_KW NUMBER { $$ = $NUMBER; }

/*
 * IP Options
 */
fw_ip_opts: fw_ip_family FROM_KW fw_ip_spec[saddr] TO_KW fw_ip_spec[daddr] fw_ip_ttl {
	// fill in ip family for any
	if ($saddr->any) {
		$saddr->family = $fw_ip_family;
	}

	if ($daddr->any) {
		$daddr->family = $fw_ip_family;
	}

	if(validate_ip($fw_ip_family, $saddr, &@saddr, config))
		YYERROR;

	if(validate_ip($fw_ip_family, $daddr, &@daddr, config))
		YYERROR;

	$$ = calloc(1, sizeof(struct fw_ip_opts));
	$$->opt_type = FW_OPT_IP;
	$$->free = &fw_ip_opts_free;
	$$->add = &fw_ip_opts_add;
	$$->print = &fw_ip_opts_print;
	$$->tail = (struct fw_opts*) $$;

	$$->family = $fw_ip_family;
	$$->daddr = $daddr;
	$$->saddr = $saddr;
	$$->ttl = $fw_ip_ttl;
}
;

fw_ip_family: IP_KW { $$ = AF_INET; }
	     | IP6_KW { $$ = AF_INET6; }
;

fw_ip_ttl: %empty { $$ = -1; }
	   | TTL_KW ANY_KW { $$ = -1; }
	   | TTL_KW NUMBER { $$ = $NUMBER; }
;

/*
 * UDP Options
 */
fw_udp_opts: UDP_KW fw_sport {
	$$ = calloc(1, sizeof(struct fw_udp_opts));

	$$->opt_type = FW_OPT_UDP;
	$$->free = &fw_udp_opts_free;
	$$->add = &fw_udp_opts_add;
	$$->print = &fw_udp_opts_print;
	$$->tail = (struct fw_opts*) $$;

	$$->sport = $fw_sport;
}
;

/*
 * TCP Option
 */
fw_tcp_opts: TCP_KW fw_sport fw_tcp_window tcp_flag_mask {
	$$ = calloc(1, sizeof(struct fw_tcp_opts));

	$$->opt_type = FW_OPT_TCP;
	$$->free = &fw_tcp_opts_free;
	$$->add = &fw_tcp_opts_add;
	$$->print = &fw_tcp_opts_print;
	$$->tail = (struct fw_opts*) $$;
	$$->window = $fw_tcp_window;
	$$->sport = $fw_sport;
	$$->flag_set = flags.flags;
	$$->mask = flags.mask;
}
;

fw_tcp_window: %empty { $$ = -1; }
	      | WINDOW_KW ANY_KW { $$ = -1; }
	      | WINDOW_KW NUMBER { $$ = $NUMBER; }
;

tcp_flag_mask: %empty { flags.flags = 0; flags.mask = 0; }
	| FLAGS_KW tcp_flags[flags] MASK_KW tcp_flags[mask] { flags.flags = $flags; flags.mask = $mask; }
	| FLAGS_KW tcp_flags { flags.flags = $tcp_flags; flags.mask = $tcp_flags; }
;

tcp_flags: %empty { $$ = 0; }
       | { flag_set = 0; } '{' tcp_flags_l '}' { $$ = flag_set; }
;

tcp_flags_l: tcp_flags_l ',' tcp_flag
	| tcp_flag
;

tcp_flag: CWR_KW { flag_set |= CWR; }
	| ECE_KW { flag_set |= ECE; }
	| URG_KW { flag_set |= URG; }
	| ACK_KW { flag_set |= ACK; }
	| PSH_KW { flag_set |= PSH; }
	| RST_KW { flag_set |= RST; }
	| SYN_KW { flag_set |= SYN; }
	| FIN_KW { flag_set |= FIN; }
;

/*
 * ICMP Option
 */
fw_icmp_opts: ICMP_KW fw_icmp_type {
		$$ = calloc(1, sizeof(struct fw_icmp_opts));

		$$->opt_type = FW_OPT_ICMP;
		$$->free = &fw_icmp_opts_free;
		$$->add = &fw_icmp_opts_add;
		$$->print = &fw_icmp_opts_print;
		$$->tail = (struct fw_opts*) $$;

		$$->family = AF_INET;
		$$->type = $fw_icmp_type;

		// Later, we make sure the icmp kw matches the address family, so save loc
		@$.first_column = @ICMP_KW.first_column;
		@$.first_line = @ICMP_KW.first_line;
		@$.last_column = @ICMP_KW.last_column;
		@$.last_line = @ICMP_KW.last_line;
}
	    | ICMP6_KW fw_icmp_type {
		$$ = calloc(1, sizeof(struct fw_icmp_opts));

		$$->opt_type = FW_OPT_ICMP;
		$$->free = &fw_icmp_opts_free;
		$$->add = &fw_icmp_opts_add;
		$$->print = &fw_icmp_opts_print;
		$$->tail = (struct fw_opts*) $$;

		$$->family = AF_INET6;
		$$->type = $fw_icmp_type;

		// Later, we make sure the icmp kw matches the address family, so save loc
		@$.first_column = @ICMP6_KW.first_column;
		@$.first_line = @ICMP6_KW.first_line;
		@$.last_column = @ICMP6_KW.last_column;
		@$.last_line = @ICMP6_KW.last_line;
}
;

fw_icmp_type: %empty { $$ = -1; }
	    | TYPE_KW ANY_KW { $$ = -1; }
	    | TYPE_KW NUMBER { $$ = $NUMBER; }

/*
 * IP List option component
 */
fw_ip_spec: '{' fw_ip_list '}'  { $$ = $fw_ip_list; }
	 | ANY_KW { $$ = calloc(1, sizeof(struct fw_ip)); $$->any = 1; $$->tail = $$; }
;

fw_ip_list: fw_ip_list ',' fw_ip { $$->tail->next = $fw_ip; $$->tail = $fw_ip; }
         | fw_ip { $$ = $fw_ip; }
;

fw_ip: IP '/' NUMBER {
		struct addrinfo hints, *res;
		int error;
		int max_mask;

		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST; // We don't do DNS
		hints.ai_socktype = SOCK_STREAM; // Whatever

		error = getaddrinfo($IP, NULL, &hints, &res);
		free($IP);

		if (error) {
			yyerror(&@IP, config, "Invalid address\n");
			YYERROR;
		}

		// Figure out the prefix
		switch (res->ai_family) {
		case AF_INET:
			max_mask=32;
			break;
		case AF_INET6:
			max_mask=128;
			break;
		}

		if ($NUMBER > max_mask || $NUMBER < 0) {
			yyerror(&@NUMBER, config, "Invalid prefix\n");
			YYERROR;
		}

		$$ = calloc(1, sizeof(struct fw_ip));
		$$->tail = $$;
		$$->family = res->ai_family;
		$$->prefix_len = $NUMBER;

		switch (res->ai_family) {
		case AF_INET:
			$$->addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
			break;
		case AF_INET6:
			$$->addr6 = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
			break;
		}

		// Create a location for the whole IP since it is error checked later
		@$.first_column = @IP.first_column;
		@$.first_line = @IP.first_line;
		@$.last_column = @NUMBER.last_column;
		@$.last_line = @NUMBER.last_line;
	}
;

/*
 * Port range option component
 */
fw_sport: %empty {
			$$ = calloc(1, sizeof(struct fw_port));
			$$->start = 1;
			$$->end = 65535;
		}
	| SPORT_KW fw_port_spec { $$ = $fw_port_spec; }
;

fw_port_spec: ANY_KW { $$ = calloc(1, sizeof(struct fw_port));
			$$->start = 1;
			$$->end = 65535;
			}
	| '{' fw_port_list '}' { $$ = $fw_port_list; }
;

fw_port_list: fw_port_list ',' fw_port { $$->tail->next = $fw_port; $$->tail = $fw_port; }
	| fw_port { $$ = $fw_port; }
;

fw_port: NUMBER {
		$$ = calloc(1, sizeof(struct fw_port));
		$$->start = $NUMBER;
		$$->end = $NUMBER;
		$$->tail = $$;
	} | NUMBER[start] '-' NUMBER[end] {
		$$ = calloc(1, sizeof(struct fw_port));
		$$->start = $start;
		$$->end = $end;
		$$->tail = $$;
	}
;
;
%%

void yyerror(YYLTYPE *locp, struct fw_cfg* config, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "%i.%i-%i.%i: ", locp->first_line, locp->first_column, locp->last_line, locp->last_column);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
}


// We don't allow mixing of v4/v6, but may in the future,
// so we loop through all IPs to verify.
int ip_has_family(int family, struct fw_ip *ip) {
	struct fw_ip *cur = ip;

	while (cur != NULL) {
		if (cur->family == family) {
			return 1;
		}
		cur = cur->next;
	}

	return 0;
}

// Right now we don't allow mixed v4/v6 rules, so the validation
// consists of making sure all the IPs are of the same family.
int validate_ip(int family, struct fw_ip *ip, YYLTYPE *locp, struct fw_cfg *config) {
	struct fw_ip *cur = ip;

	// Don't mix any and a list of addresses
	if (ip->any) {
		if (ip->next) {
			yyerror(locp, config, "An any type IP should never have a next.");
			return 1;
		}
		return 0;
	}

	// Make sure all addresses are either v4 or v6
	while (cur != NULL) {
		if (cur->family != family) {
			yyerror(locp, config, "Address family mismatch: %i vs %i", cur->family, family);
			return 1;
		}
		cur = cur->next;
	}

	return 0;
}


// Allow creation of a wildcard opt if not specified
struct fw_packet_opts *mk_fw_packet_opts(int length) {
	struct fw_packet_opts *opt;

	opt = calloc(1, sizeof(struct fw_packet_opts));

	opt->opt_type = FW_OPT_PACKET;
	opt->free = &fw_packet_opts_free;
	opt->add = &fw_packet_opts_add;
	opt->print = &fw_packet_opts_print;
	opt->tail = (struct fw_opts*) opt;

	opt->length = length;

	return opt;
}

struct fw_meta_opts *mk_fw_meta_opts(char *name) {
	struct fw_meta_opts *opt;

	opt = calloc(1, sizeof(struct fw_meta_opts));
	
	opt->opt_type = FW_OPT_META;
	opt->free = &fw_meta_opts_free;
	opt->add = &fw_meta_opts_add;
	opt->print = &fw_meta_opts_print;
	opt->tail = (struct fw_opts*) opt;

	if (name)
		opt->name = name;
	else
		opt->name = strdup("no name");

	return opt;
}


#ifdef TEST_RULES_PARSE
int main(int argc, char **argv) {
	struct fw_config *config;
	if (argc != 2) {
		printf("rules <rules-file>");
		return 1;
	}

	config = cfg_new(argv[1]);
	cfg_free(config);
}
#endif
