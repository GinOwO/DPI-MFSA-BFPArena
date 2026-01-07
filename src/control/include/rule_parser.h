/**
 * @file rule_parser.h
 * @brief Snort rule file parser for ZDPI.
 *
 * Parses Snort-style rule files and extracts PCRE patterns,
 * actions, protocols, ports, and SIDs.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.1
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_RULE_PARSER_H
#define ZDPI_RULE_PARSER_H

#include "zdpi_types.h"

#define ZDPI_MAX_LINE 2048

/**
 * @brief Parsed rule set from a file (heap-allocated).
 */
struct zdpi_ruleset {
	struct zdpi_rule *rules;
	uint32_t num_rules;
	uint32_t capacity;
};

/**
 * @brief Allocate a ruleset with given capacity.
 *
 * @param out       Output ruleset
 * @param capacity  Maximum number of rules
 * @return ZDPI_OK on success, ZDPI_ERR_NOMEM on failure
 */
int ruleset_alloc(struct zdpi_ruleset *out, uint32_t capacity);

/**
 * @brief Free ruleset resources.
 */
void ruleset_free(struct zdpi_ruleset *out);

/**
 * @brief Parse a Snort rule file into a ruleset.
 *
 * Each line should match:
 *   action proto src_ip src_port -> dst_ip dst_port (options)
 * The pcre: option is extracted as the pattern to compile.
 *
 * @param path    Path to the rule file
 * @param out     Output ruleset (must be pre-allocated via ruleset_alloc)
 * @return ZDPI_OK on success, negative error code on failure
 */
int ruleset_parse_file(const char *path, struct zdpi_ruleset *out);

/**
 * @brief Parse a single Snort rule line.
 *
 * @param line    Rule line (null-terminated)
 * @param out     Output rule (caller-allocated)
 * @return ZDPI_OK on success, ZDPI_ERR_PARSE on malformed input
 */
int rule_parse_line(const char *line, struct zdpi_rule *out);

#endif /* ZDPI_RULE_PARSER_H */
