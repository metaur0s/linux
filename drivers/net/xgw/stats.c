
static const struct {
    const char* d [DSTATS_N];
    const char* n [NSTATS_N];
    const char* p [PSTATS_N];
} statsStrs = {  // TODO: MARCAR SE ESTIVER ENVIANDO UM PING ATRASADO
    {
        [DSTATS_I_NOT_XGW               ] = "In.NotXGW",
        [DSTATS_I_DOWN                  ] = "In.Down",
        [DSTATS_I_NON_LINEAR            ] = "In.NonLinear",
        [DSTATS_I_INCOMPLETE            ] = "In.Incomplete",
        [DSTATS_I_FROM_SELF             ] = "In.FromSelf",
        [DSTATS_O_DATA_DOWN             ] = "Out.Data.Down",
        [DSTATS_O_DATA_NON_LINEAR       ] = "Out.Data.NonLinear",
        [DSTATS_O_DATA_UNKNOWN          ] = "Out.Data.Unknown",
        [DSTATS_O_DATA_TO_SELF          ] = "Out.Data.ToSelf",
        [DSTATS_O_DATA_NO_GW            ] = "Out.Data.NoGW",
        [DSTATS_O_DATA_SIZE_SMALL       ] = "Out.Data.Small",
        [DSTATS_O_DATA_SIZE_BIG         ] = "Out.Data.Big",
    }, {
        [NSTATS_I_FORWARD               ] = "In.Forward",
        [NSTATS_I_INEXIST               ] = "In.NodeInexist",
        [NSTATS_I_DISABLED              ] = "In.NodeDisabled",
        [NSTATS_I_PATH_INVALID          ] = "In.PathInvalid",
        [NSTATS_O_DATA_INEXIST          ] = "Out.Data.NodeInexist",
        [NSTATS_O_DATA_DISABLED         ] = "Out.Data.NodeDisabled",
        [NSTATS_O_DATA_MTU_EXCEEDED     ] = "Out.Data.MTUExceeded",
        [NSTATS_O_DATA_NO_PATH          ] = "Out.Data.NoPath",
    }, {
        [PSTATS_I_DATA_GOOD              ] = "In.Data.Good",
        [PSTATS_I_DATA_LCOUNTER_MISMATCH ] = "In.Data.LCounter.Bad",
        [PSTATS_I_DATA_IP4_TRUNCATED     ] = "In.Data.IP4.Truncated",
        [PSTATS_I_DATA_IP6_TRUNCATED     ] = "In.Data.IP6.Truncated",
        [PSTATS_I_NOT_PING_OR_PONG       ] = "In.NotPingOrPong",
        [PSTATS_I_DISABLED               ] = "In.Path.Disabled",
        [PSTATS_I_SIZE_TRUNCATED         ] = "In.Size.Truncated",
        [PSTATS_I_SIZE_SMALL             ] = "In.Size.Small",
        [PSTATS_I_PING_GOOD              ] = "In.Ping.Good",
        [PSTATS_I_PING_SYN_NOT_LISTENING ] = "In.Ping.Syn.NotListening",
        [PSTATS_I_PING_WHILE_CONNECTING  ] = "In.Ping.WhileConnecting",
        [PSTATS_I_PING_LCOUNTER_MISMATCH ] = "In.Ping.LCounter.Mismatch",
        [PSTATS_I_PING_RCOUNTER_INVALID  ] = "In.Ping.RCounter.Invalid",
        [PSTATS_I_PING_RCOUNTER_REPEATED ] = "In.Ping.RCounter.Repeated",
        [PSTATS_I_PING_RCOUNTER_OLD      ] = "In.Ping.RCounter.Old",
        [PSTATS_I_PING_RCOUNTER_BAD      ] = "In.Ping.RCounter.Bad",
        [PSTATS_I_PING_RACED             ] = "In.Ping.Raced",
        [PSTATS_I_PING_MISSED            ] = "In.Ping.Missed",
        [PSTATS_I_PONG_GOOD              ] = "In.Pong.Good",
        [PSTATS_I_PONG_RCOUNTER_INVALID  ] = "In.Pong.RCounter.Invalid",
        [PSTATS_I_PONG_LCOUNTER_MISMATCH ] = "In.Pong.LCounter.Mismatch",
        [PSTATS_I_PONG_MISSED            ] = "In.Pong.Missed",
        [PSTATS_O_PING_OK                ] = "Out.Ping.Ok",
        [PSTATS_O_PING_SKB_FAILED        ] = "Out.Ping.SkbFailed",
        [PSTATS_O_PING_FAILED            ] = "Out.Ping.Failed",
        [PSTATS_O_PONG_OK                ] = "Out.Pong.Ok",
        [PSTATS_O_PONG_SKB_FAILED        ] = "Out.Pong.SkbFailed",
        [PSTATS_O_PONG_FAILED            ] = "Out.Pong.Failed",
        [PSTATS_O_DATA_OK                ] = "Out.Data.Ok",
        [PSTATS_O_DATA_NO_HEADROOM       ] = "Out.Data.NoHeadroom",
        [PSTATS_O_DATA_CKSUM_FAILED      ] = "Out.Data.CksumFailed",
        [PSTATS_O_DATA_FAIL              ] = "Out.Data.Failed",
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
