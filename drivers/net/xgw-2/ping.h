
#define PING_SIZE 520
#define PONG_SIZE 64

struct ping_s {
    u64 rnd [K_LEN];
    u8 ver; // SENDER'S IKEYS INDEX BEING REGISTERED
    u8 _ [7];
};

BUILD_ASSERT(sizeof(ping_s) == PING_SIZE);
