
#define PING_SIZE_SYN    80
#define PING_SIZE_NORMAL 72
#define PONG_SIZE 72

#define PING_RANDOMS_N (K_LEN + 1)
#define PONG_RANDOMS_N 8

struct ping_s {
    u64 rnd [K_LEN];
    u8 _ [7];
    u8 ver; // SENDER'S IKEYS INDEX BEING REGISTERED
    u64 ctr; // THE PATH COUNTER
};

struct pong_s {
    u64 rnd [PONG_RANDOMS_N];
    u64 ctr; // THE PING BEING ANSWERED
};

BUILD_ASSERT(sizeof(ping_s)        == PING_SIZE_SYN);
BUILD_ASSERT(offsetof(ping_s, ctr) == PING_SIZE_NORMAL);
BUILD_ASSERT(sizeof(pong_s)        == PONG_SIZE);

BUILD_ASSERT(PING_SIZE != PONG_SIZE);
