# ZDPI Style Guide

Coding conventions for the ZDPI project, adapted from SafeCUDA for C23 + eBPF.

## Formatting

Enforced via `.clang-format`. Run `scripts/format.sh` before committing.

- **IndentWidth:** 8 (hard tabs)
- **ColumnLimit:** 80
- **PointerAlignment:** Right (`int *ptr`)
- **Braces:** Function bodies on new line; struct/if/else/for on same line (K&R variant)

## Naming

| Element            | Convention        | Example                         |
|--------------------|-------------------|---------------------------------|
| Variables          | `snake_case`      | `buffer_size`, `num_states`     |
| Functions          | `snake_case`      | `parse_rule()`, `dfa_build()`   |
| Structs/Enums      | `snake_case`      | `struct nfa_state`              |
| Constants/Macros   | `UPPER_SNAKE_CASE`| `ZDPI_MAX_STATES`               |
| BPF map names      | `snake_case`      | `arena`, `pkt_stats`            |
| Files              | `snake_case`      | `rule_parser.c`, `test_nfa.cpp` |

## Header Guards

```c
#ifndef ZDPI_MODULE_H
#define ZDPI_MODULE_H
/* ... */
#endif /* ZDPI_MODULE_H */
```

## Documentation (Doxygen)

```c
/**
 * @file module.h
 * @brief One-line description.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 1.0.0
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

/**
 * @brief Build DFA from NFA via subset construction.
 *
 * @param nfa   Source NFA
 * @param out   Output DFA (caller-allocated)
 * @return 0 on success, negative errno on error
 */
int dfa_build(const struct nfa *nfa, struct dfa *out);
```

## Error Handling

- Return 0 on success, negative errno-style codes on error.
- Use `goto cleanup` pattern for resource cleanup.
- All public functions document their error returns.

## Comments

- Doxygen docstrings on all public functions.
- Inline comments ONLY for WHY, not WHAT.
- If you need to explain what a block does, extract it into a named function.

## Include Order

1. Corresponding header (`nfa.c` includes `nfa.h` first)
2. C standard library (`<stdint.h>`, `<stdlib.h>`)
3. System/library headers (`<linux/bpf.h>`, `<bpf/libbpf.h>`)
4. Project headers (`"zdpi_types.h"`, `"regex_parser.h"`)
