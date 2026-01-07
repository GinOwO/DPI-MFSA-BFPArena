/**
 * @file zdpi_kern.bpf.c
 * @brief eBPF data plane for ZDPI deep packet inspection.
 *
 * Contains two BPF programs:
 * - SEC("syscall") zdpi_alloc: Allocates arena pages (sleepable context)
 * - SEC("xdp") zdpi_inspect: Parses packets and traverses DFA table(s)
 *
 * Supports two arena formats:
 * - V1 (version_minor=0): Single merged DFA table
 * - V2 (version_minor=1): Parallel individual DFA tables
 *
 * @author Kiran P Das
 * @date 2026-02-22
 * @version 0.2.0
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_arena_common.h"
#include "zdpi_defs.h"

/* --- BPF-side mirrors of userspace structs (uses __u32/__u16/__u8) --- */

/* V2 header used for version detection and V2 parallel DFA traversal.
 * Also serves as the common header overlay (magic + version fields). */
struct zdpi_arena_hdr_v2 {
	__u32 magic;
	__u16 version_major;
	__u16 version_minor;
	__u16 num_ec;
	__u16 num_dfas;
	__u32 dfa_dir_offset;
	__u32 ec_map_offset;
	__u32 total_size;
	__u32 table_ready;
	__u8 _pad[100];
};

struct zdpi_arena_dir_entry {
	__u32 table_offset;
	__u32 accept_offset;
	__u16 num_states;
	__u16 rule_id;
	__u8 _pad[4];
};


/* --- BPF maps --- */

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, ZDPI_ARENA_PAGES);
} arena SEC(".maps");

struct zdpi_arena_hdr_v2 __arena arena_hdr;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} pkt_stats SEC(".maps");

/* Per-CPU scratch for parallel DFA state tracking */
#define ZDPI_XDP_MAX_DFAS	1024

/* Max payload bytes to inspect per packet in XDP.
 * Smaller than ZDPI_MAX_PAYLOAD (1500) to stay within the BPF
 * verifier's 1M instruction limit when combined with bpf_loop. */
#define ZDPI_XDP_INSPECT_LEN	128

struct dfa_scratch {
	__u16 states[ZDPI_XDP_MAX_DFAS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dfa_scratch);
} dfa_state_map SEC(".maps");

/* Pre-computed equivalence class values for the current packet.
 * Filled once in traverse_v2 (which has packet access), then used
 * by bpf_loop callbacks that can't do packet pointer arithmetic. */
struct ec_cache {
	__u8 vals[ZDPI_XDP_INSPECT_LEN];
	__u32 len;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ec_cache);
} ec_cache_map SEC(".maps");

enum stat_idx {
	STAT_RX = 0,
	STAT_PASS = 1,
	STAT_DROP = 2,
	STAT_ERR = 3,
};

static __always_inline void bump_stat(__u32 idx)
{
	__u64 *val = bpf_map_lookup_elem(&pkt_stats, &idx);
	if (val)
		(*val)++;
}

SEC("syscall")
int zdpi_alloc(void *ctx)
{
	(void)&arena;
	return 0;
}

/* --- Packet parsing helpers --- */

static __always_inline int
parse_eth(void *data, void *data_end, __u16 *proto, void **next)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;

	*proto = bpf_ntohs(eth->h_proto);
	*next = (void *)(eth + 1);

	if (*proto == 0x8100) {
		struct vlan_hdr {
			__u16 tci;
			__u16 inner_proto;
		} *vlan = *next;

		if ((void *)(vlan + 1) > data_end)
			return -1;
		*proto = bpf_ntohs(vlan->inner_proto);
		*next = (void *)(vlan + 1);
	}

	return 0;
}

static __always_inline int
parse_ipv4(void *data, void *data_end, __u8 *l4_proto, void **next)
{
	struct iphdr *ip = data;

	if ((void *)(ip + 1) > data_end)
		return -1;

	__u8 ihl = ip->ihl;
	if (ihl < 5)
		return -1;

	void *l4 = data + (ihl * 4);
	if (l4 > data_end)
		return -1;

	*l4_proto = ip->protocol;
	*next = l4;
	return 0;
}

static __always_inline int
parse_transport(void *data, void *data_end, __u8 proto, void **payload,
		__u32 *payload_len)
{
	if (proto == 6) {
		struct tcphdr *tcp = data;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		__u8 doff = tcp->doff;
		if (doff < 5)
			return -1;
		void *p = data + (doff * 4);
		if (p > data_end)
			return -1;
		*payload = p;
		*payload_len = (__u32)(data_end - p);
	} else if (proto == 17) {
		struct udphdr *udp = data;
		if ((void *)(udp + 1) > data_end)
			return -1;
		*payload = (void *)(udp + 1);
		*payload_len = (__u32)(data_end - *payload);
	} else {
		return -1;
	}
	return 0;
}

/* V1 single-DFA traversal removed no longer produced by control plane. */

/* --- V2 parallel DFA traversal (DFA-major with early exit) --- */

/*
 * Two-level bpf_loop structure (DFA-major order):
 *   Outer bpf_loop: iterate over DFAs       (run_one_dfa)
 *   Inner bpf_loop: iterate over bytes       (scan_byte)
 *
 * This gives us DFA-count callbacks at the outer level (e.g. 6),
 * each with byte-count callbacks at the inner level.  Each DFA
 * exits its byte scan immediately on dead state, so clean traffic
 * that doesn't match any pattern bails after just 1-3 bytes per DFA.
 *
 * Previous byte-major approach: 256 × 1024 = 262k bpf_loop callbacks.
 * New DFA-major approach: 6 outer bpf_loop callbacks, each with a
 * direct 256-byte loop (no inner bpf_loop overhead).
 */

/* Context for outer DFA loop. */
struct dfa_loop_ctx {
	__u8 *bk;
	struct zdpi_arena_dir_entry *dir;
	struct ec_cache *ecc;
	__u16 num_ec;
	__u16 num_dfas;
	__u8 matched;
};

/* Outer bpf_loop callback: run one DFA over all payload bytes.
 * Uses a direct bounded loop over pre-computed EC values instead of
 * nested bpf_loop eliminates 256 callback invocations per DFA. */
static long run_one_dfa(__u32 di, void *_ctx)
{
	struct dfa_loop_ctx *ctx = _ctx;

	/* Compile-time constant bound for verifier map access proof */
	if (di >= ZDPI_XDP_MAX_DFAS)
		return 1;
	if (di >= ctx->num_dfas)
		return 1;

	struct zdpi_arena_dir_entry *entry = &ctx->dir[di];
	__u16 ns = entry->num_states;
	if (ns == 0)
		return 0;

	__u16 *tbl = (__u16 *)(ctx->bk + entry->table_offset);
	__u8 *acc = ctx->bk + entry->accept_offset;
	__u16 num_ec = ctx->num_ec;
	__u16 state = ZDPI_START_STATE;
	struct ec_cache *ecc = ctx->ecc;
	__u32 len = ecc->len;

	/* Direct bounded loop over EC cache no bpf_loop overhead.
	 * The verifier can prove termination via constant upper bound. */
	for (__u32 i = 0; i < ZDPI_XDP_INSPECT_LEN; i++) {
		if (i >= len)
			break;

		__u8 ec = ecc->vals[i];
		if (ec >= num_ec)
			break;
		if (state >= ns)
			break;

		__u32 idx = (__u32)state * num_ec + ec;
		state = tbl[idx];

		if (state == ZDPI_DEAD_STATE)
			break;

		if (state < ns) {
			__u32 bi = state / 8;
			__u8 bm = 1 << (state % 8);
			if (acc[bi] & bm) {
				ctx->matched = 1;
				return 1; /* match found */
			}
		}
	}

	return 0; /* continue to next DFA */
}

static __always_inline int
traverse_v2(__u8 __arena *base, void *payload, void *data_end,
	    __u32 payload_len)
{
	struct zdpi_arena_hdr_v2 __arena *hdr =
		(struct zdpi_arena_hdr_v2 __arena *)base;
	cast_kern(hdr);

	if (!hdr->table_ready)
		return XDP_PASS;

	__u16 num_ec = hdr->num_ec;
	__u16 num_dfas = hdr->num_dfas;

	if (num_ec == 0 || num_dfas == 0)
		return XDP_PASS;
	if (num_ec > ZDPI_MAX_EC)
		return XDP_PASS;
	if (num_dfas > ZDPI_XDP_MAX_DFAS)
		num_dfas = ZDPI_XDP_MAX_DFAS;

	/* Cast arena base to kernel pointer BPF verifier prohibits
	 * variable-offset arithmetic on arena pointers. */
	cast_kern(base);
	__u8 *bk = (__u8 *)base;

	__u8 *ec_map = bk + ZDPI_EC_MAP_V2_OFFSET;
	struct zdpi_arena_dir_entry *dir =
		(struct zdpi_arena_dir_entry *)(bk + ZDPI_DFA_DIR_OFFSET);

	__u32 max_len = payload_len;
	if (max_len > ZDPI_XDP_INSPECT_LEN)
		max_len = ZDPI_XDP_INSPECT_LEN;

	/* Pre-compute EC values from packet into per-CPU cache.
	 * This must happen here (not in bpf_loop callbacks) because
	 * the verifier can't track packet pointer bounds across
	 * callback boundaries. */
	__u32 ecc_key = 0;
	struct ec_cache *ecc =
		bpf_map_lookup_elem(&ec_cache_map, &ecc_key);
	if (!ecc)
		return XDP_PASS;

	__u32 actual_len = 0;
	for (__u32 i = 0; i < ZDPI_XDP_INSPECT_LEN; i++) {
		if (i >= max_len)
			break;
		__u8 *bp = (__u8 *)payload + i;
		if ((void *)(bp + 1) > data_end)
			break;
		__u8 ec = ec_map[*bp];
		if (ec >= num_ec)
			break;
		ecc->vals[i] = ec;
		actual_len = i + 1;
	}
	ecc->len = actual_len;

	if (actual_len == 0)
		return XDP_PASS;

	struct dfa_loop_ctx ctx = {
		.bk = bk,
		.dir = dir,
		.ecc = ecc,
		.num_ec = num_ec,
		.num_dfas = num_dfas,
		.matched = 0,
	};

	bpf_loop(ZDPI_XDP_MAX_DFAS, run_one_dfa, &ctx, 0);

	return ctx.matched ? XDP_DROP : XDP_PASS;
}

/* --- V4 AC + MFSA two-stage traversal --- */

struct zdpi_arena_hdr_v4 {
	__u32 magic;
	__u16 version_major;
	__u16 version_minor;		/* 3 = AC+MFSA */
	__u16 ac_num_ec;
	__u16 _pad0;
	__u32 ac_num_states;
	__u32 ac_table_offset;
	__u32 ac_accept_offset;
	__u32 ac_matchdir_offset;
	__u32 ac_matchlist_offset;
	__u32 ac_matchlist_count;
	__u16 mfsa_num_ec;
	__u16 mfsa_num_dfas;
	__u32 mfsa_ec_offset;
	__u32 mfsa_dir_offset;
	__u32 always_run_offset;
	__u32 always_run_count;
	__u32 total_size;
	__u32 table_ready;
	__u8 _pad[64];
};

/* Per-CPU scratch for v4: matched MFSA DFA bitmask */
struct v4_scratch {
	__u8 matched_dfas[ZDPI_XDP_MAX_DFAS / 8]; /* 128 bytes */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct v4_scratch);
} v4_scratch_map SEC(".maps");

/* Force the compiler to materialize a value so subsequent masking
 * isn't folded into prior arithmetic.  Without this, clang merges
 * (x >> 3) & 127 into (x & 0x3F8) >> 3, and the verifier never
 * sees the & 127 that proves the map-value bound. */
#define bpf_barrier_var(v) asm volatile("" : "+r"(v))

/* --- V4 helpers and bpf_loop callbacks --- */

/* --- V4 AC chunked traversal ---
 *
 * Process 128 payload bytes in 32 chunks of 4 bytes each via bpf_loop.
 * This gives 32 callback invocations (vs 128 in the per-byte approach),
 * reducing callback overhead by 4x while staying within verifier limits. */

#define AC_CHUNK_SIZE	4
#define AC_NUM_CHUNKS	(ZDPI_XDP_INSPECT_LEN / AC_CHUNK_SIZE) /* 16 */

struct ac_chunk_ctx {
	struct ec_cache *raw;
	__u8 *ac_ecm;
	__u16 *ac_tbl;
	__u8 *ac_acc;
	__u32 *matchdir;
	__u16 *matchlist;
	struct v4_scratch *scratch;
	__u32 ac_num_states;
	__u32 matchlist_count;
	__u16 ac_num_ec;
	__u16 ac_state;
	__u32 raw_len;
};

/* Process one match from AC accept state's match list */
static __always_inline void
ac_set_match_bit(struct v4_scratch *scratch, __u16 dfa_idx)
{
	if (dfa_idx < ZDPI_XDP_MAX_DFAS) {
		__u32 bi = dfa_idx >> 3;
		bpf_barrier_var(bi);
		bi &= (ZDPI_XDP_MAX_DFAS / 8 - 1);
		__u8 bbit = 1 << (dfa_idx & 7);
		scratch->matched_dfas[bi] |= bbit;
	}
}

static long ac_process_chunk(__u32 chunk, void *_ctx)
{
	struct ac_chunk_ctx *ctx = _ctx;
	__u32 base_i = chunk * AC_CHUNK_SIZE;

	if (base_i >= ctx->raw_len)
		return 1;

	__u16 ac_state = ctx->ac_state;

	/* Process up to AC_CHUNK_SIZE bytes in this chunk */
	for (__u32 j = 0; j < AC_CHUNK_SIZE; j++) {
		__u32 i = base_i + j;
		if (i >= ctx->raw_len)
			break;

		/* Mask i for verifier bounds proof on vals[] */
		__u32 vi = i & (ZDPI_XDP_INSPECT_LEN - 1);
		__u8 ec = ctx->ac_ecm[ctx->raw->vals[vi]];
		if (ec >= ctx->ac_num_ec) {
			ac_state = ZDPI_START_STATE;
			continue;
		}

		if (ac_state >= ctx->ac_num_states)
			ac_state = ZDPI_START_STATE;

		__u32 idx = (__u32)ac_state * ctx->ac_num_ec + ec;
		ac_state = ctx->ac_tbl[idx];

		if (ac_state == ZDPI_DEAD_STATE)
			ac_state = ZDPI_START_STATE;

		/* Check AC accept set match bits.
		 * Manually unrolled (no loop) to avoid verifier
		 * state explosion on ENA kernels. */
		if (ac_state < ctx->ac_num_states &&
		    (ctx->ac_acc[ac_state / 8] &
		     (1 << (ac_state % 8)))) {
			__u32 entry = ctx->matchdir[ac_state];
			__u32 m_off = entry >> 16;
			__u32 m_cnt = entry & 0xFFFF;
			__u32 mlc = ctx->matchlist_count;
			if (m_cnt > 0 && m_off < mlc)
				ac_set_match_bit(ctx->scratch,
					ctx->matchlist[m_off]);
			if (m_cnt > 1 && m_off + 1 < mlc)
				ac_set_match_bit(ctx->scratch,
					ctx->matchlist[m_off + 1]);
			if (m_cnt > 2 && m_off + 2 < mlc)
				ac_set_match_bit(ctx->scratch,
					ctx->matchlist[m_off + 2]);
			if (m_cnt > 3 && m_off + 3 < mlc)
				ac_set_match_bit(ctx->scratch,
					ctx->matchlist[m_off + 3]);
		}
	}

	ctx->ac_state = ac_state;
	return 0;
}

/* Context for always-run DFA processing callback */
struct always_run_ctx {
	__u16 *always_run;
	struct v4_scratch *scratch;
	__u32 ar_count;
};

static long ac_set_always_run(__u32 i, void *_ctx)
{
	struct always_run_ctx *ctx = _ctx;

	if (i >= ctx->ar_count)
		return 1;

	__u16 ar_idx = ctx->always_run[i];
	if (ar_idx < ZDPI_XDP_MAX_DFAS) {
		__u32 bi = ar_idx >> 3;
		bpf_barrier_var(bi);
		bi &= (ZDPI_XDP_MAX_DFAS / 8 - 1);
		__u8 bbit = 1 << (ar_idx & 7);
		ctx->scratch->matched_dfas[bi] |= bbit;
	}

	return 0;
}

/* Context for v4 MFSA DFA loop callback */
struct dfa_loop_ctx_v4 {
	__u8 *bk;
	struct zdpi_arena_dir_entry *dir;
	struct ec_cache *raw;	/* raw packet bytes */
	__u8 *mfsa_ecm;		/* MFSA EC map */
	struct v4_scratch *scratch;
	__u16 num_ec;
	__u16 num_dfas;
	__u32 raw_len;
	__u8 matched;
};

static long run_one_dfa_v4(__u32 di, void *_ctx)
{
	struct dfa_loop_ctx_v4 *ctx = _ctx;

	if (di >= ZDPI_XDP_MAX_DFAS)
		return 1;
	if (di >= ctx->num_dfas)
		return 1;

	/* Check if this DFA was selected by AC stage.
	 * Barrier + mask so verifier sees the bound. */
	__u32 byte_idx = di >> 3;
	bpf_barrier_var(byte_idx);
	byte_idx &= (ZDPI_XDP_MAX_DFAS / 8 - 1);
	__u8 bit_mask = 1 << (di & 7);
	if (!(ctx->scratch->matched_dfas[byte_idx] & bit_mask))
		return 0; /* skip: not matched by AC */

	struct zdpi_arena_dir_entry *entry = &ctx->dir[di];
	__u16 ns = entry->num_states;
	if (ns == 0)
		return 0;

	__u16 *tbl = (__u16 *)(ctx->bk + entry->table_offset);
	__u8 *acc = ctx->bk + entry->accept_offset;
	__u16 num_ec = ctx->num_ec;
	__u16 state = ZDPI_START_STATE;
	struct ec_cache *raw = ctx->raw;
	__u32 len = ctx->raw_len;

	for (__u32 i = 0; i < ZDPI_XDP_INSPECT_LEN; i++) {
		if (i >= len)
			break;

		__u8 ec = ctx->mfsa_ecm[raw->vals[i]];
		if (ec >= num_ec)
			break;
		if (state >= ns)
			break;

		__u32 idx = (__u32)state * num_ec + ec;
		state = tbl[idx];

		if (state == ZDPI_DEAD_STATE)
			break;

		if (state < ns) {
			__u32 bi = state / 8;
			__u8 bm = 1 << (state % 8);
			if (acc[bi] & bm) {
				ctx->matched = 1;
				return 1;
			}
		}
	}

	return 0;
}

static __always_inline int
traverse_v4(__u8 __arena *base, void *payload, void *data_end,
	    __u32 payload_len)
{
	struct zdpi_arena_hdr_v4 __arena *hdr =
		(struct zdpi_arena_hdr_v4 __arena *)base;
	cast_kern(hdr);

	if (!hdr->table_ready)
		return XDP_PASS;

	__u16 ac_num_ec = hdr->ac_num_ec;
	__u32 ac_num_states = hdr->ac_num_states;
	__u16 mfsa_num_ec = hdr->mfsa_num_ec;
	__u16 mfsa_num_dfas = hdr->mfsa_num_dfas;

	if (ac_num_ec == 0 || ac_num_states == 0)
		return XDP_PASS;
	if (ac_num_ec > ZDPI_MAX_EC)
		return XDP_PASS;
	if (mfsa_num_dfas > ZDPI_XDP_MAX_DFAS)
		mfsa_num_dfas = ZDPI_XDP_MAX_DFAS;

	cast_kern(base);
	__u8 *bk = (__u8 *)base;

	/* AC section pointers */
	__u8 *ac_ecm = bk + ZDPI_HEADER_V4_SIZE;
	__u16 *ac_tbl = (__u16 *)(bk + hdr->ac_table_offset);
	__u8 *ac_acc = bk + hdr->ac_accept_offset;
	__u32 *matchdir = (__u32 *)(bk + hdr->ac_matchdir_offset);
	__u16 *matchlist = (__u16 *)(bk + hdr->ac_matchlist_offset);
	__u32 matchlist_count = hdr->ac_matchlist_count;

	/* Get per-CPU v4 scratch */
	__u32 s_key = 0;
	struct v4_scratch *scratch =
		bpf_map_lookup_elem(&v4_scratch_map, &s_key);
	if (!scratch)
		return XDP_PASS;

	/* Clear matched_dfas bitmask */
	volatile __u64 *bm64 = (volatile __u64 *)scratch->matched_dfas;
	for (__u32 w = 0; w < (ZDPI_XDP_MAX_DFAS / 8 / 8); w++)
		bm64[w] = 0;

	/* --- Cache raw packet bytes --- */
	__u32 ecc_key = 0;
	struct ec_cache *raw =
		bpf_map_lookup_elem(&ec_cache_map, &ecc_key);
	if (!raw)
		return XDP_PASS;

	__u32 max_len = payload_len;
	if (max_len > ZDPI_XDP_INSPECT_LEN)
		max_len = ZDPI_XDP_INSPECT_LEN;

	__u32 raw_len = 0;
	for (__u32 i = 0; i < ZDPI_XDP_INSPECT_LEN; i++) {
		if (i >= max_len)
			break;
		__u8 *bp = (__u8 *)payload + i;
		if ((void *)(bp + 1) > data_end)
			break;
		raw->vals[i] = *bp;
		raw_len = i + 1;
	}
	raw->len = raw_len;

	if (raw_len == 0)
		return XDP_PASS;

	/* --- Stage 1: AC traversal via chunked bpf_loop ---
	 * 16 chunks of 8 bytes each = 16 callbacks instead of 128.
	 * 8x less callback overhead than per-byte bpf_loop. */
	struct ac_chunk_ctx ac_ctx = {
		.raw = raw,
		.ac_ecm = ac_ecm,
		.ac_tbl = ac_tbl,
		.ac_acc = ac_acc,
		.matchdir = matchdir,
		.matchlist = matchlist,
		.scratch = scratch,
		.ac_num_states = ac_num_states,
		.matchlist_count = matchlist_count,
		.ac_num_ec = ac_num_ec,
		.ac_state = ZDPI_START_STATE,
		.raw_len = raw_len,
	};

	bpf_loop(AC_NUM_CHUNKS, ac_process_chunk, &ac_ctx, 0);

	/* OR in always-run DFAs via bpf_loop */
	__u16 *always_run = (__u16 *)(bk + hdr->always_run_offset);
	__u32 ar_count = hdr->always_run_count;
	if (ar_count > ZDPI_XDP_MAX_DFAS)
		ar_count = ZDPI_XDP_MAX_DFAS;

	struct always_run_ctx ar_ctx = {
		.always_run = always_run,
		.scratch = scratch,
		.ar_count = ar_count,
	};
	bpf_loop(ar_count, ac_set_always_run, &ar_ctx, 0);

	/* Quick check: any bits set in matched_dfas? */
	int any_set = 0;
	for (__u32 w = 0; w < (ZDPI_XDP_MAX_DFAS / 8 / 8); w++) {
		if (bm64[w]) {
			any_set = 1;
			break;
		}
	}
	if (!any_set)
		return XDP_PASS;

	/* --- Stage 2: MFSA parallel DFA traversal --- */
	__u8 *mfsa_ecm = bk + hdr->mfsa_ec_offset;
	struct zdpi_arena_dir_entry *mdir =
		(struct zdpi_arena_dir_entry *)(bk + hdr->mfsa_dir_offset);

	struct dfa_loop_ctx_v4 ctx = {
		.bk = bk,
		.dir = mdir,
		.raw = raw,
		.mfsa_ecm = mfsa_ecm,
		.scratch = scratch,
		.num_ec = mfsa_num_ec,
		.num_dfas = mfsa_num_dfas,
		.raw_len = raw_len,
		.matched = 0,
	};

	bpf_loop(ZDPI_XDP_MAX_DFAS, run_one_dfa_v4, &ctx, 0);

	return ctx.matched ? XDP_DROP : XDP_PASS;
}

/* --- Common packet parse + dispatch helper --- */

static __always_inline int
xdp_parse_payload(struct xdp_md *ctx, void **payload_out,
		  void **data_end_out, __u32 *payload_len_out)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 eth_proto;
	__u8 l4_proto;
	void *l3, *l4, *payload;
	__u32 payload_len;

	if (parse_eth(data, data_end, &eth_proto, &l3))
		return -1;
	if (eth_proto != 0x0800)
		return -1;
	if (parse_ipv4(l3, data_end, &l4_proto, &l4))
		return -1;
	if (parse_transport(l4, data_end, l4_proto, &payload, &payload_len))
		return -1;
	if (payload_len == 0)
		return -1;

	*payload_out = payload;
	*data_end_out = data_end;
	*payload_len_out = payload_len;
	return 0;
}

/* --- V2 XDP program (parallel DFA only) --- */

SEC("xdp")
int zdpi_inspect_v2(struct xdp_md *ctx)
{
	void *payload, *data_end;
	__u32 payload_len;

	bump_stat(STAT_RX);

	if (xdp_parse_payload(ctx, &payload, &data_end, &payload_len))
		goto pass;

	__u8 __arena *base = (__u8 __arena *)&arena_hdr;
	struct zdpi_arena_hdr_v2 __arena *hdr =
		(struct zdpi_arena_hdr_v2 __arena *)base;
	cast_kern(hdr);

	if (hdr->magic != ZDPI_MAGIC)
		goto pass;

	int action = traverse_v2(base, payload, data_end, payload_len);
	if (action == XDP_DROP) {
		bump_stat(STAT_DROP);
		return XDP_DROP;
	}

pass:
	bump_stat(STAT_PASS);
	return XDP_PASS;
}

/* --- V4 XDP program (AC + MFSA two-stage) --- */

SEC("xdp")
int zdpi_inspect_v4(struct xdp_md *ctx)
{
	void *payload, *data_end;
	__u32 payload_len;

	bump_stat(STAT_RX);

	if (xdp_parse_payload(ctx, &payload, &data_end, &payload_len))
		goto pass;

	__u8 __arena *base = (__u8 __arena *)&arena_hdr;
	struct zdpi_arena_hdr_v4 __arena *hdr =
		(struct zdpi_arena_hdr_v4 __arena *)base;
	cast_kern(hdr);

	if (hdr->magic != ZDPI_MAGIC)
		goto pass;

	int action = traverse_v4(base, payload, data_end, payload_len);
	if (action == XDP_DROP) {
		bump_stat(STAT_DROP);
		return XDP_DROP;
	}

pass:
	bump_stat(STAT_PASS);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
