
// STATISTICS

// NOTE: THOSE ORDERS MUST CONSIDER CACHE USAGE

// INTERFACE
// TODO: GLOBAL STATS VS PHYS STATS (PER ITFC INDEX)
enum DSTATS {
    DSTATS_I_NOT_XGW, // PASS
    DSTATS_I_NON_LINEAR,
    DSTATS_I_INCOMPLETE,
    DSTATS_I_FROM_SELF,
    DSTATS_O_DATA_DOWN,
    DSTATS_O_DATA_NON_LINEAR,
    DSTATS_O_DATA_UNKNOWN,
    DSTATS_O_DATA_TO_SELF,
    DSTATS_O_DATA_NO_GW,
    DSTATS_O_DATA_SIZE_SMALL,
    DSTATS_O_DATA_SIZE_BIG,
    DSTATS_N
};

// NODE
enum NSTATS {
    NSTATS_I_FORWARD, // PASS
    NSTATS_I_INEXIST,
    NSTATS_I_DISABLED,
    NSTATS_I_DOWN,
    NSTATS_I_PATH_INVALID,
    NSTATS_O_DATA_INEXIST,
    NSTATS_O_DATA_DISABLED,
    NSTATS_O_DATA_MTU_EXCEEDED,
    NSTATS_O_DATA_NO_PATH,
    NSTATS_N
};

// PATH
enum PSTATS {

    PSTATS_I_DATA_GOOD, // PASS
    PSTATS_I_DATA_LCOUNTER_MISMATCH,
    PSTATS_I_DATA_IP4_TRUNCATED,
    PSTATS_I_DATA_IP6_TRUNCATED,

    PSTATS_I_DISABLED,
    PSTATS_I_SIZE_TRUNCATED,
    PSTATS_I_SIZE_SMALL,

    PSTATS_I_NOT_PING_OR_PONG,

    PSTATS_I_PING_GOOD,
    PSTATS_I_PING_SYN_NOT_LISTENING,
    PSTATS_I_PING_WHILE_CONNECTING,
    PSTATS_I_PING_RCOUNTER_INVALID,
    PSTATS_I_PING_RCOUNTER_REPEATED,
    PSTATS_I_PING_RCOUNTER_OLD,
    PSTATS_I_PING_RCOUNTER_BAD,
    PSTATS_I_PING_LCOUNTER_MISMATCH,
    PSTATS_I_PING_RACED,
    PSTATS_I_PING_MISSED,

    PSTATS_I_PONG_GOOD,
    PSTATS_I_PONG_RCOUNTER_INVALID,
    PSTATS_I_PONG_LCOUNTER_MISMATCH,
    PSTATS_I_PONG_MISSED, // TODO: IMPLEMENTAR ISSO!!!

    PSTATS_O_PING_OK,
    PSTATS_O_PING_SKB_FAILED,
    PSTATS_O_PING_FAILED,

    PSTATS_O_PONG_OK,
    PSTATS_O_PONG_SKB_FAILED,
    PSTATS_O_PONG_FAILED,

    PSTATS_O_DATA_OK,
    PSTATS_O_DATA_NO_HEADROOM,
    PSTATS_O_DATA_CKSUM_FAILED,
    PSTATS_O_DATA_FAIL,

    PSTATS_N
};

struct stat_s {
    u64 count;
    u64 bytes; // NOTE: ALGUNS STATS TERAO O COUNT/BYTES CONSIDERANDO O PACOTE REAL E NAO ENCAPSULADO
};

// TODO: OUT {ping, pong, data} _PHYS_DOWN
// TODO: OUT {ping, pong, data} _PHYS_NO_CARRIER

#define ret_dev(i)  { stat = i; goto _ret_dev;  }
#define ret_node(i) { stat = i; goto _ret_node; }
#define ret_path(i) { stat = i; goto _ret_path; }
