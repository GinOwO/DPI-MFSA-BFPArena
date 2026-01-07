/**
 * @file arena_flash.c
 * @brief BPF skeleton loader, arena writer, and XDP attacher.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.1
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "arena_flash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "zdpi_types.h"
#include "zdpi_log.h"

/* The BPF skeleton references BPF-side struct names.
 * Map them to the userspace equivalents from zdpi_types.h. */
#define zdpi_arena_hdr zdpi_table_header
#define zdpi_arena_hdr_v2 zdpi_table_header_v2
#define zdpi_arena_dir_entry zdpi_dfa_dir_entry

/* Per-CPU scratch struct for parallel DFA state tracking.
 * Must match the BPF-side definition (ZDPI_XDP_MAX_DFAS=1024). */
#define ZDPI_XDP_MAX_DFAS 1024
struct dfa_scratch {
	uint16_t states[ZDPI_XDP_MAX_DFAS];
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#include "zdpi_kern.skel.h"
#pragma GCC diagnostic pop

int arena_flash(const struct arena_blob *blob, const char *ifname,
		int xdp_version, struct zdpi_handle *handle)
{
	memset(handle, 0, sizeof(*handle));

	unsigned int ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		LOG_ERR("Interface not found: %s", ifname);
		return ZDPI_ERR_IO;
	}

	LOG_DBG("Opening BPF skeleton...");
	struct zdpi_kern_bpf *skel = zdpi_kern_bpf__open();
	if (!skel) {
		LOG_ERR("Failed to open BPF skeleton");
		return ZDPI_ERR_BPF;
	}

	/* Disable autoload on the XDP program we don't need
	 * loading both would exceed the verifier's 1M insn limit. */
	if (xdp_version == ZDPI_XDP_V4)
		bpf_program__set_autoload(skel->progs.zdpi_inspect_v2,
					  false);
	else
		bpf_program__set_autoload(skel->progs.zdpi_inspect_v4,
					  false);

	LOG_DBG("Loading BPF programs...");
	int err = zdpi_kern_bpf__load(skel);
	if (err) {
		LOG_ERR("Failed to load BPF: %d", err);
		zdpi_kern_bpf__destroy(skel);
		return ZDPI_ERR_BPF;
	}

	/* Get the arena mapping set up by libbpf during skeleton load. */
	size_t arena_sz = 0;
	void *arena_ptr = bpf_map__initial_value(skel->maps.arena,
						 &arena_sz);
	if (!arena_ptr) {
		LOG_ERR("Failed to get arena mapping");
		zdpi_kern_bpf__destroy(skel);
		return ZDPI_ERR_BPF;
	}
	LOG_DBG("Arena mapped: %zu bytes", arena_sz);

	/* Allocate arena pages in kernel via the SEC("syscall") program. */
	int prog_fd = bpf_program__fd(skel->progs.zdpi_alloc);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	int ret = topts.retval;
	if (err || ret) {
		LOG_ERR("Arena alloc failed: err=%d ret=%d", err, ret);
		zdpi_kern_bpf__destroy(skel);
		return ZDPI_ERR_BPF;
	}

	/* Copy the linearized DFA table into the arena. */
	LOG_DBG("Flashing %u bytes to arena...", blob->size);
	memcpy(arena_ptr, blob->data, blob->size);

	/* Select the right XDP program based on arena version. */
	struct bpf_program *xdp_prog;
	if (xdp_version == ZDPI_XDP_V4)
		xdp_prog = skel->progs.zdpi_inspect_v4;
	else
		xdp_prog = skel->progs.zdpi_inspect_v2;

	/* Use SKB (generic) XDP mode BPF arena addr_space_cast is not
	 * supported by most NIC drivers' native XDP path. */
	int prog_fd_xdp = bpf_program__fd(xdp_prog);
	LOG_DBG("Attaching XDP (SKB mode) to %s (ifindex %u)...",
		ifname, ifindex);
	err = bpf_xdp_attach((int)ifindex, prog_fd_xdp,
			      XDP_FLAGS_SKB_MODE, NULL);
	if (err) {
		LOG_ERR("Failed to attach XDP to %s: %s",
			ifname, strerror(-err));
		zdpi_kern_bpf__destroy(skel);
		return ZDPI_ERR_BPF;
	}

	handle->skel = skel;
	handle->ifindex = (int)ifindex;

	return ZDPI_OK;
}

void arena_detach(struct zdpi_handle *handle)
{
	if (handle->ifindex > 0)
		bpf_xdp_detach(handle->ifindex, XDP_FLAGS_SKB_MODE,
				NULL);
	if (handle->skel) {
		zdpi_kern_bpf__destroy(handle->skel);
		handle->skel = NULL;
	}
	handle->ifindex = 0;
}

void arena_print_stats(const struct zdpi_handle *handle)
{
	if (!handle->skel)
		return;

	const struct zdpi_kern_bpf *skel = handle->skel;
	int fd = bpf_map__fd(skel->maps.pkt_stats);

	static const char *stat_names[] = { "RX", "PASS", "DROP", "ERR" };

	printf("\n--- Packet Statistics ---\n");
	for (uint32_t i = 0; i < 4; i++) {
		uint64_t values[256] = { 0 };
		uint32_t key = i;
		int err = bpf_map_lookup_elem(fd, &key, values);
		if (err)
			continue;

		uint64_t total = 0;
		int ncpus = libbpf_num_possible_cpus();
		for (int c = 0; c < ncpus && c < 256; c++)
			total += values[c];

		printf("  %-6s: %lu\n", stat_names[i], total);
	}
}
