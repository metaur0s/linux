
#define STAT_NAME(a) [a] = #a

static const struct {
    const char* d [DSTATS_N];
    const char* n [NSTATS_N];
    const char* p [PSTATS_N];
} statsStrs = {  // TODO: MARCAR SE ESTIVER ENVIANDO UM PING ATRASADO
    {
        STAT_NAME(DSTATS_I_NOT_XGW),
        STAT_NAME(DSTATS_I_NON_LINEAR),
        STAT_NAME(DSTATS_I_INCOMPLETE),
        STAT_NAME(DSTATS_I_FROM_SELF),
        STAT_NAME(DSTATS_O_DATA_DOWN),
        STAT_NAME(DSTATS_O_DATA_NON_LINEAR),
        STAT_NAME(DSTATS_O_DATA_UNKNOWN),
        STAT_NAME(DSTATS_O_DATA_TO_SELF),
        STAT_NAME(DSTATS_O_DATA_NO_GW),
        STAT_NAME(DSTATS_O_DATA_SIZE_SMALL),
        STAT_NAME(DSTATS_O_DATA_SIZE_BIG),
    }, {
        STAT_NAME(NSTATS_I_FORWARD),
        STAT_NAME(NSTATS_I_INEXIST),
        STAT_NAME(NSTATS_I_DISABLED),
        STAT_NAME(NSTATS_I_DOWN),
        STAT_NAME(NSTATS_I_PATH_INVALID),
        STAT_NAME(NSTATS_O_DATA_INEXIST),
        STAT_NAME(NSTATS_O_DATA_DISABLED),
        STAT_NAME(NSTATS_O_DATA_MTU_EXCEEDED),
        STAT_NAME(NSTATS_O_DATA_NO_PATH),
    }, {
        STAT_NAME(PSTATS_I_DATA_GOOD),
        STAT_NAME(PSTATS_I_DATA_IP4_TRUNCATED),
        STAT_NAME(PSTATS_I_DATA_IP6_TRUNCATED),
        STAT_NAME(PSTATS_I_DISABLED),
        STAT_NAME(PSTATS_I_SIZE_SMALL),
        STAT_NAME(PSTATS_I_SIZE_NOT_PING),
        STAT_NAME(PSTATS_I_SIZE_TRUNCATED),
        STAT_NAME(PSTATS_I_HASH_MISMATCH),
        STAT_NAME(PSTATS_I_LISTENING_SYN_TOO_MANY),
        STAT_NAME(PSTATS_I_LISTENING_NOT_SYN_OR_PING),
        STAT_NAME(PSTATS_I_ACCEPTING),
        STAT_NAME(PSTATS_I_CONNECTING_NOT_PONG),
        STAT_NAME(PSTATS_I_ESTABLISHED_SYN),
        STAT_NAME(PSTATS_I_LTIME_MISMATCH_SYN_OR_PONG),
        STAT_NAME(PSTATS_I_LTIME_MISMATCH_SYN),
        STAT_NAME(PSTATS_I_LTIME_MISMATCH_PING_SENT),
        STAT_NAME(PSTATS_I_LTIME_MISMATCH),
        STAT_NAME(PSTATS_I_LTIME_SKEW),
        STAT_NAME(PSTATS_I_RTIME_INVALID),
        STAT_NAME(PSTATS_I_RTIME_BACKWARDS),
        STAT_NAME(PSTATS_I_RTIME_SKEW),
        STAT_NAME(PSTATS_I_PING_GOOD_ACCEPT_RACED),
        STAT_NAME(PSTATS_I_PING_GOOD),
        STAT_NAME(PSTATS_I_PING_SYN_NOT_LISTENING),
        STAT_NAME(PSTATS_I_PING_MISSED),
        STAT_NAME(PSTATS_I_PONG_RACED),
        STAT_NAME(PSTATS_I_PONG_GOOD),
        STAT_NAME(PSTATS_I_PONG_MISSED),
        STAT_NAME(PSTATS_O_PING_OK),
        STAT_NAME(PSTATS_O_PING_SKB_FAILED),
        STAT_NAME(PSTATS_O_PING_FAILED),
        STAT_NAME(PSTATS_O_PONG_OK),
        STAT_NAME(PSTATS_O_PONG_SKB_FAILED),
        STAT_NAME(PSTATS_O_PONG_SEND_FAILED),
        STAT_NAME(PSTATS_O_DATA_OK),
        STAT_NAME(PSTATS_O_DATA_NO_HEADROOM),
        STAT_NAME(PSTATS_O_DATA_CKSUM_FAILED),
        STAT_NAME(PSTATS_O_DATA_FAIL),
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
