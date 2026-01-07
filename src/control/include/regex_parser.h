/**
 * @file regex_parser.h
 * @brief PCRE-subset regex parser for ZDPI.
 *
 * Converts a PCRE pattern string into a postfix token stream
 * suitable for Thompson's NFA construction. Supports:
 *   - Literal characters
 *   - Concatenation (implicit)
 *   - Alternation (|)
 *   - Kleene star (*), plus (+), optional (?)
 *   - Character classes ([a-z], [^...])
 *   - Dot (.) wildcard
 *   - Grouping with parentheses
 *   - Escape sequences (\d, \w, \s, \., \\, etc.)
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.1
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_REGEX_PARSER_H
#define ZDPI_REGEX_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#define RE_MAX_TOKENS 4096

/**
 * @brief Token types for the postfix regex representation.
 */
enum re_token_type {
	RE_TOK_LITERAL = 0,
	RE_TOK_DOT,
	RE_TOK_CONCAT,
	RE_TOK_ALTER,
	RE_TOK_STAR,
	RE_TOK_PLUS,
	RE_TOK_QUEST,
	RE_TOK_CLASS,
	RE_TOK_LPAREN,
	RE_TOK_RPAREN,
};

/**
 * @brief Character class: set of 256 bits (one per byte value).
 */
struct re_char_class {
	uint8_t bits[32];
};

/**
 * @brief Single token in the postfix stream.
 */
struct re_token {
	enum re_token_type type;
	union {
		uint8_t literal;
		struct re_char_class cclass;
	};
};

/**
 * @brief Postfix token stream output from the parser.
 */
struct re_token_stream {
	struct re_token tokens[RE_MAX_TOKENS];
	uint32_t len;
};

/**
 * @brief Parse a PCRE pattern into a postfix token stream.
 *
 * Uses the shunting-yard algorithm to handle operator precedence.
 * Inserts explicit concatenation operators where implicit.
 *
 * @param pattern  Null-terminated PCRE pattern (without delimiters)
 * @param out      Output token stream (caller-allocated)
 * @return 0 on success, ZDPI_ERR_PARSE on syntax error,
 *         ZDPI_ERR_OVERFLOW on token limit exceeded
 */
int regex_parse(const char *pattern, struct re_token_stream *out);

/**
 * @brief Set a bit in a character class.
 */
static inline void cc_set(struct re_char_class *cc, uint8_t c)
{
	cc->bits[c / 8] |= (1 << (c % 8));
}

/**
 * @brief Test a bit in a character class.
 */
static inline bool cc_test(const struct re_char_class *cc, uint8_t c)
{
	return (cc->bits[c / 8] >> (c % 8)) & 1;
}

/**
 * @brief Clear all bits in a character class.
 */
static inline void cc_clear(struct re_char_class *cc)
{
	for (int i = 0; i < 32; i++)
		cc->bits[i] = 0;
}

/**
 * @brief Set all bits in a character class.
 */
static inline void cc_fill(struct re_char_class *cc)
{
	for (int i = 0; i < 32; i++)
		cc->bits[i] = 0xFF;
}

#endif /* ZDPI_REGEX_PARSER_H */
