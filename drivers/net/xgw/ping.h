
#define PING_SIZE (PING_RANDOMS_N * sizeof(u64))
#define PONG_SIZE (PONG_RANDOMS_N * sizeof(u64))

#define PING_RANDOMS_N (K_LEN + 1)
#define PONG_RANDOMS_N 16

struct ping_s {
    u64 rnd [K_LEN];
    u8 _ [7];
    u8 ver; // SENDER'S IKEYS INDEX BEING REGISTERED
};

BUILD_ASSERT(sizeof(ping_s) == PING_SIZE);

BUILD_ASSERT(PING_SIZE != PONG_SIZE);
