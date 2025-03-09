
#define __STAT(a) [a] = #a

static const struct {
    const char* d [DSTATS_N];
    const char* n [NSTATS_N];
    const char* p [PSTATS_N];
} statsStrs = {  // TODO: MARCAR SE ESTIVER ENVIANDO UM PING ATRASADO
    {
        [DSTATS_I_NOT_XGW               ] = "In.Pass",
        [DSTATS_I_NON_LINEAR            ] = "In.NonLinear",
        [DSTATS_I_INCOMPLETE            ] = "In.Incomplete",
        [DSTATS_I_FROM_SELF             ] = "In.FromSelf",
        [DSTATS_O_DATA_DOWN             ] = "Out.Data.Down",
        [DSTATS_O_DATA_NON_LINEAR       ] = "Out.Data.NonLinear",
        [DSTATS_O_DATA_UNKNOWN          ] = "Out.Data.Unknown",
        [DSTATS_O_DATA_TO_SELF          ] = "Out.Data.ToSelf",
        [DSTATS_O_DATA_NO_GW            ] = "Out.Data.ToUnknown", // TO AN UNKNOWN NODE (NO GATEWAY)
        [DSTATS_O_DATA_SIZE_SMALL       ] = "Out.Data.Small",
        [DSTATS_O_DATA_SIZE_BIG         ] = "Out.Data.Big",
    }, {
        [NSTATS_I_FORWARD               ] = "In.Forward",
        [NSTATS_I_INEXIST               ] = "In.NodeInexist",
        [NSTATS_I_DISABLED              ] = "In.NodeDisabled",
        [NSTATS_I_DOWN                  ] = "In.Down",
        [NSTATS_I_PATH_INVALID          ] = "In.PathInvalid",
        [NSTATS_O_DATA_INEXIST          ] = "Out.Data.NodeInexist",
        [NSTATS_O_DATA_DISABLED         ] = "Out.Data.NodeDisabled",
        [NSTATS_O_DATA_MTU_EXCEEDED     ] = "Out.Data.MTUExceeded",
        [NSTATS_O_DATA_NO_PATH          ] = "Out.Data.NoPath",
    }, {
        __STAT(PSTATS_I_DATA_GOOD),
        __STAT(PSTATS_I_HASH_MISMATCH),
        __STAT(PSTATS_I_WHILE_ACCEPTING),
        __STAT(PSTATS_I_NOT_PING),
        __STAT(PSTATS_I_NOT_PONG),
        __STAT(PSTATS_I_PING_BAD_SIZE),
        __STAT(PSTATS_I_SYN_WHILE_ESTABLISHED),
        __STAT(PSTATS_I_SYN_TOO_MANY),
        __STAT(PSTATS_I_LTIME_NOT_SYN),
        __STAT(PSTATS_I_LTIME_MISMATCH),
        __STAT(PSTATS_I_NOT_SYN_OR_PING),
        __STAT(PSTATS_I_RTIME_INVALID),
        __STAT(PSTATS_I_RTIME_BACKWARDS),
        __STAT(PSTATS_I_RTIME_SKEW_UP),
        __STAT(PSTATS_I_RTIME_SKEW_DOWN),
        __STAT(PSTATS_I_PONG_RACED),
        __STAT(PSTATS_I_PONG_OK),
        __STAT(PSTATS_I_ACCEPT_RACED),
        __STAT(PSTATS_I_DATA_IP4_TRUNCATED),
        __STAT(PSTATS_I_DATA_IP6_TRUNCATED),
        __STAT(PSTATS_I_NOT_PING_OR_PONG),
        __STAT(PSTATS_I_DISABLED),
        __STAT(PSTATS_I_SIZE_TRUNCATED),
        __STAT(PSTATS_I_SIZE_SMALL),
        __STAT(PSTATS_I_PING_SYN_NOT_LISTENING),
        __STAT(PSTATS_I_PING_WHILE_CONNECTING),
        __STAT(PSTATS_I_PING_GOOD_ANSWER_SKB_ALLOC_FAILED),
        __STAT(PSTATS_I_PING_GOOD_ANSWER_SEND_FAILED),
        __STAT(PSTATS_I_PING_GOOD),
        __STAT(PSTATS_I_PING_MISSED),
        __STAT(PSTATS_I_PONG_GOOD),
        __STAT(PSTATS_I_PONG_MISSED),
        __STAT(PSTATS_O_PING_OK),
        __STAT(PSTATS_O_PING_SKB_FAILED),
        __STAT(PSTATS_O_PING_FAILED),
        __STAT(PSTATS_O_PONG_OK),
        __STAT(PSTATS_O_PONG_SKB_FAILED),
        __STAT(PSTATS_O_PONG_FAILED),
        __STAT(PSTATS_O_DATA_OK),
        __STAT(PSTATS_O_DATA_NO_HEADROOM),
        __STAT(PSTATS_O_DATA_CKSUM_FAILED),
        __STAT(PSTATS_O_DATA_FAIL),
    }
};

static void __cold_as_ice __optimize_size stats_print (void) {

    for_count (s, DSTATS_N) {
        const uintll c = atomic_get(&(dstats[s].count));
        const uintll b = atomic_get(&(dstats[s].bytes));
        if (c || b)
            printk("XGW: %s %llu %llu\n", statsStrs.d[s], c, b);
    }

    for_count (nid, NODES_N) {

        const node_s* const node = nodes_get_locked_unsuspended(nid);

        if (node) {

            for_count (s, NSTATS_N) {
                const uintll c = atomic_get(&(nstats[nid][s].count));
                const uintll b = atomic_get(&(nstats[nid][s].bytes));
                if (c || b)
                    printk("XGW: %s %s %llu %llu\n", node->name, statsStrs.n[s], c, b);
            }

            for_count (pid, PATHS_N) {

                const path_s* const path = &node->paths[pid];

                if (path->info) {
                    for_count (s, PSTATS_N) {
                        const uintll c = atomic_get(&(node->pstats[pid][s].count));
                        const uintll b = atomic_get(&(node->pstats[pid][s].bytes));
                        if (c || b)
                            printk("XGW: %s [%s] %s %llu %llu\n", node->name, path->name, statsStrs.p[s], c, b);
                    }
                }
            }
        }
    }
}
