/**
 * @file rule_parser.c
 * @brief Snort rule file parser implementation.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.1
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "rule_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int parse_action(const char **p, uint8_t *action)
{
	while (isspace(**p))
		(*p)++;

	if (strncmp(*p, "alert", 5) == 0) {
		*action = ZDPI_ACTION_DROP;
		*p += 5;
	} else if (strncmp(*p, "pass", 4) == 0) {
		*action = ZDPI_ACTION_PASS;
		*p += 4;
	} else if (strncmp(*p, "drop", 4) == 0) {
		*action = ZDPI_ACTION_DROP;
		*p += 4;
	} else {
		return ZDPI_ERR_PARSE;
	}
	return ZDPI_OK;
}

static int parse_proto(const char **p, uint8_t *proto)
{
	while (isspace(**p))
		(*p)++;

	if (strncmp(*p, "tcp-pkt", 7) == 0) {
		*proto = 6;
		*p += 7;
	} else if (strncmp(*p, "tcp", 3) == 0) {
		*proto = 6;
		*p += 3;
	} else if (strncmp(*p, "udp", 3) == 0) {
		*proto = 17;
		*p += 3;
	} else if (strncmp(*p, "http", 4) == 0) {
		*proto = 6;
		*p += 4;
	} else if (strncmp(*p, "tls", 3) == 0) {
		*proto = 6;
		*p += 3;
	} else if (strncmp(*p, "dns", 3) == 0) {
		*proto = 17;
		*p += 3;
	} else if (strncmp(*p, "smtp", 4) == 0) {
		*proto = 6;
		*p += 4;
	} else if (strncmp(*p, "ftp-data", 8) == 0) {
		*proto = 6;
		*p += 8;
	} else if (strncmp(*p, "ftp", 3) == 0) {
		*proto = 6;
		*p += 3;
	} else if (strncmp(*p, "ssh", 3) == 0) {
		*proto = 6;
		*p += 3;
	} else if (strncmp(*p, "smb", 3) == 0) {
		*proto = 6;
		*p += 3;
	} else if (strncmp(*p, "icmp", 4) == 0) {
		*proto = 1;
		*p += 4;
	} else if (strncmp(*p, "ip", 2) == 0) {
		*proto = 0;
		*p += 2;
	} else {
		return ZDPI_ERR_PARSE;
	}
	return ZDPI_OK;
}

static void skip_field(const char **p)
{
	while (isspace(**p))
		(*p)++;
	while (**p && !isspace(**p))
		(*p)++;
}

static int parse_port(const char *token, uint16_t *port)
{
	if (strcmp(token, "any") == 0 || token[0] == '$' ||
	    token[0] == '[' || token[0] == '!') {
		*port = 0;
		return ZDPI_OK;
	}
	char *end;
	long val = strtol(token, &end, 10);
	if (val < 0 || val > 65535) {
		*port = 0;
		return ZDPI_OK;
	}
	*port = (uint16_t)val;
	return ZDPI_OK;
}

static int extract_pcre(const char *options, char *pcre_out,
			uint32_t *pcre_len)
{
	const char *p = strstr(options, "pcre:\"");
	if (!p)
		p = strstr(options, "pcre: \"");
	if (!p)
		return ZDPI_ERR_PARSE;

	/* Find opening delimiter */
	p = strchr(p, '"');
	if (!p)
		return ZDPI_ERR_PARSE;
	p++;

	if (*p != '/')
		return ZDPI_ERR_PARSE;
	p++;

	/* Find closing delimiter: /[flags]"
	 * Flags can be any letter (i, s, m, x, R, U, B, etc.) */
	const char *end = p;
	while (*end) {
		if (*end == '\\' && end[1]) {
			end += 2;
			continue;
		}
		if (*end == '/') {
			const char *f = end + 1;
			while (isalpha(*f))
				f++;
			if (*f == '"')
				break;
		}
		end++;
	}

	if (*end != '/')
		return ZDPI_ERR_PARSE;

	uint32_t len = (uint32_t)(end - p);
	if (len >= 512)
		return ZDPI_ERR_OVERFLOW;

	memcpy(pcre_out, p, len);
	pcre_out[len] = '\0';
	*pcre_len = len;
	return ZDPI_OK;
}

static int extract_contents(const char *options, struct zdpi_rule *out)
{
	out->num_contents = 0;
	const char *p = options;

	while ((p = strstr(p, "content:")) != NULL) {
		/* Make sure this isn't a substring of another keyword */
		if (p > options && (isalnum(p[-1]) || p[-1] == '_')) {
			p += 8;
			continue;
		}

		p += 8; /* skip "content:" */
		while (isspace(*p))
			p++;

		if (out->num_contents >= ZDPI_MAX_CONTENTS)
			break;

		struct zdpi_content *c =
			&out->contents[out->num_contents];
		memset(c, 0, sizeof(*c));

		/* Check for negation */
		if (*p == '!') {
			c->negated = true;
			p++;
		}

		if (*p != '"') {
			continue;
		}
		p++; /* skip opening quote */

		/* Parse content value handles "text" and |HH HH| hex */
		uint32_t len = 0;
		while (*p && *p != '"' && len < ZDPI_MAX_CONTENT_LEN) {
			if (*p == '|') {
				/* Hex escape sequence |HH HH ...| */
				p++;
				while (*p && *p != '|') {
					while (isspace(*p))
						p++;
					if (*p == '|')
						break;
					if (isxdigit(p[0]) &&
					    isxdigit(p[1])) {
						char hex[3] = {
							p[0], p[1], 0
						};
						c->data[len++] =
							(uint8_t)strtol(
								hex,
								NULL, 16);
						p += 2;
					} else {
						p++;
					}
				}
				if (*p == '|')
					p++;
			} else {
				c->data[len++] = (uint8_t)*p;
				p++;
			}
		}

		if (*p == '"')
			p++;

		if (len == 0)
			continue;

		c->len = len;

		/* Check for nocase modifier after this content */
		const char *semi = strchr(p, ';');
		if (semi) {
			/* Look for nocase; before next content: or end */
			const char *next_content = strstr(p, "content:");
			const char *nocase_pos = strstr(p, "nocase");
			if (nocase_pos &&
			    (!next_content ||
			     nocase_pos < next_content)) {
				c->nocase = true;
				/* Lowercase the data for AC */
				for (uint32_t i = 0; i < c->len; i++) {
					if (c->data[i] >= 'A' &&
					    c->data[i] <= 'Z')
						c->data[i] += 32;
				}
			}
		}

		out->num_contents++;
	}

	return ZDPI_OK;
}

static int extract_sid(const char *options, uint32_t *sid)
{
	const char *p = strstr(options, "sid:");
	if (!p) {
		*sid = 0;
		return ZDPI_OK;
	}
	p += 4;
	while (isspace(*p))
		p++;
	*sid = (uint32_t)strtol(p, NULL, 10);
	return ZDPI_OK;
}

int rule_parse_line(const char *line, struct zdpi_rule *out)
{
	memset(out, 0, sizeof(*out));

	/* Skip comment/empty lines */
	const char *p = line;
	while (isspace(*p))
		p++;
	if (*p == '#' || *p == '\0' || *p == '\n')
		return ZDPI_ERR_PARSE;

	int rc;

	rc = parse_action(&p, &out->action);
	if (rc)
		return rc;

	rc = parse_proto(&p, &out->proto);
	if (rc)
		return rc;

	/* Skip: src_ip src_port -> dst_ip dst_port */
	skip_field(&p); /* src_ip */

	while (isspace(*p))
		p++;
	char port_buf[16] = { 0 };
	int pi = 0;
	while (*p && !isspace(*p) && pi < 15)
		port_buf[pi++] = *p++;
	port_buf[pi] = '\0';
	parse_port(port_buf, &out->src_port);

	skip_field(&p); /* -> */
	skip_field(&p); /* dst_ip */

	while (isspace(*p))
		p++;
	pi = 0;
	memset(port_buf, 0, sizeof(port_buf));
	while (*p && !isspace(*p) && *p != '(' && pi < 15)
		port_buf[pi++] = *p++;
	port_buf[pi] = '\0';
	parse_port(port_buf, &out->dst_port);

	/* Find options in parentheses */
	const char *opts = strchr(p, '(');
	if (!opts)
		return ZDPI_ERR_PARSE;

	/* Extract content fields (optional rules may have only pcre) */
	extract_contents(opts, out);

	rc = extract_pcre(opts, out->pcre, &out->pcre_len);
	if (rc)
		return rc;

	extract_sid(opts, &out->sid);

	return ZDPI_OK;
}

int ruleset_alloc(struct zdpi_ruleset *out, uint32_t capacity)
{
	out->rules = calloc(capacity, sizeof(struct zdpi_rule));
	if (!out->rules)
		return ZDPI_ERR_NOMEM;
	out->num_rules = 0;
	out->capacity = capacity;
	return ZDPI_OK;
}

void ruleset_free(struct zdpi_ruleset *out)
{
	if (!out)
		return;
	free(out->rules);
	out->rules = NULL;
	out->num_rules = 0;
	out->capacity = 0;
}

int ruleset_parse_file(const char *path, struct zdpi_ruleset *out)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
		return ZDPI_ERR_IO;

	out->num_rules = 0;
	char line[ZDPI_MAX_LINE];

	while (fgets(line, sizeof(line), fp)) {
		/* Strip newline */
		size_t len = strlen(line);
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';

		/* Skip blank/comment lines */
		const char *p = line;
		while (isspace(*p))
			p++;
		if (*p == '#' || *p == '\0')
			continue;

		if (out->num_rules >= out->capacity) {
			fclose(fp);
			return ZDPI_ERR_OVERFLOW;
		}

		int rc = rule_parse_line(line,
					 &out->rules[out->num_rules]);
		if (rc == ZDPI_OK)
			out->num_rules++;
		/* Silently skip unparseable lines */
	}

	fclose(fp);

	if (out->num_rules == 0)
		return ZDPI_ERR_PARSE;

	return ZDPI_OK;
}
