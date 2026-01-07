#ifndef STUB_ARENA_H
#define STUB_ARENA_H

#ifdef ZDPI_TESTING
#include <stdint.h>

static uint8_t stub_arena_mem[4 * 1024 * 1024];
static void *stub_table_base = stub_arena_mem;
static uint32_t stub_table_ready = 0;

#endif /* ZDPI_TESTING */

#endif /* STUB_ARENA_H */
