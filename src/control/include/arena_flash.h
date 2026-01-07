/**
 * @file arena_flash.h
 * @brief BPF skeleton loader and arena writer for ZDPI.
 *
 * Opens the BPF skeleton, runs the syscall program to allocate
 * arena pages, copies the linearized table into the arena,
 * and attaches the XDP program to a network interface.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.1
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_ARENA_FLASH_H
#define ZDPI_ARENA_FLASH_H

#include <stdint.h>
#include "linearize.h"

/**
 * @brief Handle for an active BPF program + XDP attachment.
 */
struct zdpi_handle {
	void *skel;
	int ifindex;
};

/**
 * @brief Flash a linearized table into the BPF arena and attach XDP.
 *
 * Steps:
 * 1. Open + load BPF skeleton
 * 2. Run SEC("syscall") to allocate arena pages
 * 3. memcpy blob data into arena mmap region
 * 4. Attach XDP program to the given interface
 *
 * @param blob     Linearized arena blob
 * @param ifname   Network interface name (e.g. "eth0")
 * @param handle   Output handle for later detach
 * @return 0 on success, ZDPI_ERR_BPF on BPF error, ZDPI_ERR_IO on interface error
 */
/**
 * @brief Version hint for selecting the right XDP program.
 */
#define ZDPI_XDP_V2	1	/* parallel DFA only */
#define ZDPI_XDP_V4	3	/* AC + MFSA two-stage */

int arena_flash(const struct arena_blob *blob, const char *ifname,
		int xdp_version, struct zdpi_handle *handle);

/**
 * @brief Detach XDP and destroy the BPF skeleton.
 *
 * @param handle   Handle from arena_flash()
 */
void arena_detach(struct zdpi_handle *handle);

/**
 * @brief Print per-CPU packet statistics from BPF maps.
 *
 * @param handle   Active handle
 */
void arena_print_stats(const struct zdpi_handle *handle);

#endif /* ZDPI_ARENA_FLASH_H */
