
struct ping_s {
    u64 rnd [K_LEN] [K_WORDS];
    u8 ver; // SENDER'S IKEYS INDEX BEING REGISTERED
    u8 _ [7];
    u64 ctr; // SENDER'S COUNTER
};

struct pong_s {
    u64 rnd [8];
    u64 ctr; // SENDER'S COUNTER
};

BUILD_ASSERT(sizeof(ping_s) == 528);
BUILD_ASSERT(sizeof(pong_s) == 72);
