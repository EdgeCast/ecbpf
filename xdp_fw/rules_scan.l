%option noyywrap
%{
#pragma clang diagnostic ignored "-Wimplicit-fallthrough"
#include <string.h>
#include <sysexits.h>
#include <err.h>
#include <string.h>
#include "rules.h"

void yyerror(char *);

#include "y.tab.h"

#define QUOTE_MAX 4096
#define YY_USER_ACTION {yylloc->first_line = yylloc->last_line = yylineno; \
			yylloc->first_column = offset; \
			offset+=yyleng; \
			yylloc->last_column=offset;}

int offset = 1;
char quote_str[QUOTE_MAX];
int quote_str_idx;

%}

ip [0-9a-fA-F:\.]+
number [0-9]+
sha1 [0-9a-fA-F]{40}

%option bison-locations
%option yylineno
%x COMMENT
%x QUOTE

%%
packet { return PACKET_KW; }
length { return LENGTH_KW; }

ip { return IP_KW; }
ip6 { return IP6_KW; }
any { return ANY_KW; }
from { return FROM_KW; }
to { return TO_KW; }
ttl { return TTL_KW; }
[/] { return *yytext; }
name { return NAME_KW; }

tcp { return TCP_KW; }
window { return WINDOW_KW; }
flags { return FLAGS_KW; }
mask { return MASK_KW; }
cwr { return CWR_KW; }
ece { return ECE_KW; }
urg { return URG_KW; }
ack { return ACK_KW; }
psh { return PSH_KW; }
rst { return RST_KW; }
syn { return SYN_KW; }
fin { return FIN_KW; }

icmp { return ICMP_KW; }
icmp6 { return ICMP6_KW; }
type { return TYPE_KW; }

udp { return UDP_KW; }
sport { return SPORT_KW; }

test { return TEST_KW; }
sha1 { return SHA1_KW; }
xdp_action { return XDP_ACTION_KW; }

XDP_PASS { yylval->act = XDP_PASS; return XDP_ACTION; }
XDP_DROP { yylval->act = XDP_DROP; return XDP_ACTION; }
XDP_ABORTED { yylval->act = XDP_ABORTED; return XDP_ACTION; }

{sha1} {
	char *pos = yytext;

	for (int i = 0; i < sizeof(yylval->sha1); i++) {
		sscanf(pos, "%2hhx", &yylval->sha1[i]);
		pos += 2;
	}

	return SHA1;
}

{number} {
	yylval->number = atoi(yytext);
	return NUMBER;
}

{ip} {
	yylval->string = strdup(yytext);

	return IP;
}

[{},-] { return yytext[0];}

"#" { BEGIN COMMENT; }
<COMMENT>.* ;
<COMMENT>\n { BEGIN INITIAL; offset=1; return EOL; }
\n	{ offset=1; return EOL;}
[ \t]+					/* ignore whitespace */;

[\"] {
	BEGIN QUOTE;
	quote_str_idx = 0;
}
<QUOTE>[^\"\n] {
	quote_str[quote_str_idx++] = yytext[0]; 
	 if (quote_str_idx >= QUOTE_MAX) {
		fprintf(stderr, "Quoted string on line %i exceeded max length of %i", yylineno, QUOTE_MAX);
		exit(1);
	}

}
<QUOTE>[\n] {
	fprintf(stderr, "Unterminated string on line %i\n", yylineno);
	exit(1);
}
<QUOTE>[\"] {
	BEGIN INITIAL;
	quote_str[quote_str_idx] = '\0';
	yylval->string = strdup(quote_str);
	return QUOTED_STRING;
}
%%
