/**
 * @file regex_parser.c
 * @brief PCRE-subset regex to postfix token stream converter.
 *
 * Uses the shunting-yard algorithm to convert infix regex notation
 * with implicit concatenation into an explicit postfix token stream.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.1
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "regex_parser.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "zdpi_types.h"

static void build_shorthand(struct re_char_class *cc, char which)
{
	cc_clear(cc);
	switch (which) {
	case 'd':
		for (int c = '0'; c <= '9'; c++)
			cc_set(cc, (uint8_t)c);
		break;
	case 'D':
		cc_fill(cc);
		for (int c = '0'; c <= '9'; c++)
			cc->bits[c / 8] &= ~(1 << (c % 8));
		break;
	case 'w':
		for (int c = 'a'; c <= 'z'; c++)
			cc_set(cc, (uint8_t)c);
		for (int c = 'A'; c <= 'Z'; c++)
			cc_set(cc, (uint8_t)c);
		for (int c = '0'; c <= '9'; c++)
			cc_set(cc, (uint8_t)c);
		cc_set(cc, '_');
		break;
	case 'W':
		cc_fill(cc);
		for (int c = 'a'; c <= 'z'; c++)
			cc->bits[c / 8] &= ~(1 << (c % 8));
		for (int c = 'A'; c <= 'Z'; c++)
			cc->bits[c / 8] &= ~(1 << (c % 8));
		for (int c = '0'; c <= '9'; c++)
			cc->bits[c / 8] &= ~(1 << (c % 8));
		cc->bits['_' / 8] &= ~(1 << ('_' % 8));
		break;
	case 's':
		cc_set(cc, ' ');
		cc_set(cc, '\t');
		cc_set(cc, '\n');
		cc_set(cc, '\r');
		cc_set(cc, '\f');
		cc_set(cc, '\v');
		break;
	case 'S':
		cc_fill(cc);
		cc->bits[' ' / 8] &= ~(1 << (' ' % 8));
		cc->bits['\t' / 8] &= ~(1 << ('\t' % 8));
		cc->bits['\n' / 8] &= ~(1 << ('\n' % 8));
		cc->bits['\r' / 8] &= ~(1 << ('\r' % 8));
		cc->bits['\f' / 8] &= ~(1 << ('\f' % 8));
		cc->bits['\v' / 8] &= ~(1 << ('\v' % 8));
		break;
	}
}

static int parse_char_class(const char **p, struct re_char_class *cc)
{
	cc_clear(cc);
	bool negated = false;

	if (**p == '^') {
		negated = true;
		(*p)++;
	}

	while (**p && **p != ']') {
		uint8_t lo = (uint8_t)**p;
		(*p)++;

		/* Escape inside class */
		if (lo == '\\' && **p) {
			char esc = **p;
			(*p)++;
			if (esc == 'd' || esc == 'D' || esc == 'w' ||
			    esc == 'W' || esc == 's' || esc == 'S') {
				struct re_char_class sub;
				build_shorthand(&sub, esc);
				for (int i = 0; i < 32; i++)
					cc->bits[i] |= sub.bits[i];
				continue;
			}
			if (esc == 'x' && isxdigit(**p)) {
				char hex[3] = { **p, 0, 0 };
				(*p)++;
				if (isxdigit(**p)) {
					hex[1] = **p;
					(*p)++;
				}
				lo = (uint8_t)strtol(hex, NULL, 16);
			} else {
				lo = (uint8_t)esc;
			}
		}

		/* Range: a-z */
		if (**p == '-' && (*p)[1] && (*p)[1] != ']') {
			(*p)++;
			uint8_t hi = (uint8_t)**p;
			(*p)++;
			if (hi == '\\' && **p) {
				char esc2 = **p;
				(*p)++;
				if (esc2 == 'x' && isxdigit(**p)) {
					char hex2[3] = { **p, 0, 0 };
					(*p)++;
					if (isxdigit(**p)) {
						hex2[1] = **p;
						(*p)++;
					}
					hi = (uint8_t)strtol(
						hex2, NULL, 16);
				} else {
					hi = (uint8_t)esc2;
				}
			}
			for (int c = lo; c <= hi; c++)
				cc_set(cc, (uint8_t)c);
		} else {
			cc_set(cc, lo);
		}
	}

	if (**p == ']')
		(*p)++;

	if (negated) {
		for (int i = 0; i < 32; i++)
			cc->bits[i] = ~cc->bits[i];
	}

	return 0;
}

static int precedence(enum re_token_type t)
{
	switch (t) {
	case RE_TOK_ALTER:
		return 1;
	case RE_TOK_CONCAT:
		return 2;
	case RE_TOK_STAR:
	case RE_TOK_PLUS:
	case RE_TOK_QUEST:
		return 3;
	default:
		return 0;
	}
}

static int emit(struct re_token_stream *out, struct re_token *tok)
{
	if (out->len >= RE_MAX_TOKENS)
		return ZDPI_ERR_OVERFLOW;
	out->tokens[out->len++] = *tok;
	return 0;
}

int regex_parse(const char *pattern, struct re_token_stream *out)
{
	memset(out, 0, sizeof(*out));

	/* First pass: tokenize with explicit concat, using dedicated
	 * LPAREN/RPAREN types so escaped parens are never ambiguous. */
	struct re_token infix[RE_MAX_TOKENS];
	uint32_t infix_len = 0;
	bool prev_operand = false;

	const char *p = pattern;
	while (*p) {
		if (infix_len >= RE_MAX_TOKENS)
			return ZDPI_ERR_OVERFLOW;

		struct re_token tok = { 0 };

		switch (*p) {
		case '(':
			if (prev_operand) {
				if (infix_len >= RE_MAX_TOKENS)
					return ZDPI_ERR_OVERFLOW;
				struct re_token concat = {
					.type = RE_TOK_CONCAT
				};
				infix[infix_len++] = concat;
			}
			tok.type = RE_TOK_LPAREN;
			infix[infix_len++] = tok;
			prev_operand = false;
			p++;
			continue;

		case ')':
			tok.type = RE_TOK_RPAREN;
			infix[infix_len++] = tok;
			prev_operand = true;
			p++;
			continue;

		case '|':
			tok.type = RE_TOK_ALTER;
			infix[infix_len++] = tok;
			prev_operand = false;
			p++;
			continue;

		case '*':
			tok.type = RE_TOK_STAR;
			infix[infix_len++] = tok;
			prev_operand = true;
			p++;
			continue;

		case '+':
			tok.type = RE_TOK_PLUS;
			infix[infix_len++] = tok;
			prev_operand = true;
			p++;
			continue;

		case '?':
			tok.type = RE_TOK_QUEST;
			infix[infix_len++] = tok;
			prev_operand = true;
			p++;
			continue;

		case '.':
			if (prev_operand) {
				if (infix_len >= RE_MAX_TOKENS)
					return ZDPI_ERR_OVERFLOW;
				struct re_token concat = {
					.type = RE_TOK_CONCAT
				};
				infix[infix_len++] = concat;
			}
			tok.type = RE_TOK_DOT;
			infix[infix_len++] = tok;
			prev_operand = true;
			p++;
			continue;

		case '[':
			if (prev_operand) {
				if (infix_len >= RE_MAX_TOKENS)
					return ZDPI_ERR_OVERFLOW;
				struct re_token concat = {
					.type = RE_TOK_CONCAT
				};
				infix[infix_len++] = concat;
			}
			p++;
			tok.type = RE_TOK_CLASS;
			parse_char_class(&p, &tok.cclass);
			infix[infix_len++] = tok;
			prev_operand = true;
			continue;

		case '\\':
			p++;
			if (!*p)
				return ZDPI_ERR_PARSE;

			if (prev_operand) {
				if (infix_len >= RE_MAX_TOKENS)
					return ZDPI_ERR_OVERFLOW;
				struct re_token concat = {
					.type = RE_TOK_CONCAT
				};
				infix[infix_len++] = concat;
			}

			if (*p == 'd' || *p == 'D' || *p == 'w' ||
			    *p == 'W' || *p == 's' || *p == 'S') {
				tok.type = RE_TOK_CLASS;
				build_shorthand(&tok.cclass, *p);
			} else if (*p == 'x' && isxdigit(p[1])) {
				/* \xNN hex escape */
				p++;
				char hex[3] = { p[0], 0, 0 };
				if (isxdigit(p[1])) {
					hex[1] = p[1];
					p++;
				}
				tok.type = RE_TOK_LITERAL;
				tok.literal =
					(uint8_t)strtol(hex, NULL, 16);
			} else {
				tok.type = RE_TOK_LITERAL;
				tok.literal = (uint8_t)*p;
			}
			infix[infix_len++] = tok;
			prev_operand = true;
			p++;
			continue;

		default:
			if (prev_operand) {
				if (infix_len >= RE_MAX_TOKENS)
					return ZDPI_ERR_OVERFLOW;
				struct re_token concat = {
					.type = RE_TOK_CONCAT
				};
				infix[infix_len++] = concat;
			}
			tok.type = RE_TOK_LITERAL;
			tok.literal = (uint8_t)*p;
			infix[infix_len++] = tok;
			prev_operand = true;
			p++;
			continue;
		}
	}

	/* Second pass: shunting-yard to postfix */
	struct re_token op_stack[RE_MAX_TOKENS];
	uint32_t op_top = 0;

	for (uint32_t i = 0; i < infix_len; i++) {
		struct re_token *t = &infix[i];

		if (t->type == RE_TOK_LPAREN) {
			op_stack[op_top++] = *t;
			continue;
		}

		if (t->type == RE_TOK_RPAREN) {
			while (op_top > 0) {
				struct re_token *top =
					&op_stack[op_top - 1];
				if (top->type == RE_TOK_LPAREN) {
					op_top--;
					break;
				}
				int rc = emit(out, top);
				if (rc)
					return rc;
				op_top--;
			}
			continue;
		}

		/* Operands go straight to output */
		if (t->type == RE_TOK_LITERAL || t->type == RE_TOK_DOT ||
		    t->type == RE_TOK_CLASS) {
			int rc = emit(out, t);
			if (rc)
				return rc;
			continue;
		}

		/* Operators: pop higher/equal precedence, then push */
		while (op_top > 0) {
			struct re_token *top = &op_stack[op_top - 1];
			if (top->type == RE_TOK_LPAREN)
				break;
			if (precedence(top->type) >= precedence(t->type)) {
				int rc = emit(out, top);
				if (rc)
					return rc;
				op_top--;
			} else {
				break;
			}
		}
		op_stack[op_top++] = *t;
	}

	/* Pop remaining operators */
	while (op_top > 0) {
		struct re_token *top = &op_stack[op_top - 1];
		if (top->type == RE_TOK_LPAREN)
			return ZDPI_ERR_PARSE; /* Unmatched paren */
		int rc = emit(out, top);
		if (rc)
			return rc;
		op_top--;
	}

	return ZDPI_OK;
}
