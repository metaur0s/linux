
#define PING_SIZE 528
#define PONG_SIZE 136

#define PING_RANDOMS_N (K_LEN + 1)
#define PONG_RANDOMS_N 16

struct ping_s {
    u64 rnd [K_LEN];
    u8 _ [7];
    u8 ver; // SENDER'S IKEYS INDEX BEING REGISTERED
    u64 scounter; // SENDER'S LCOUNTER
};

struct pong_s {
    u64 rnd [16];
    u64 scounter; // SENDER'S LCOUNTER
};

BUILD_ASSERT(sizeof(ping_s) == PING_SIZE);
BUILD_ASSERT(sizeof(pong_s) == PONG_SIZE);
