
#define PING_SIZE 520
#define PONG_SIZE 64

union ping_s {
    struct {
        u64 rnd [K_LEN] [K_WORDS];
        u8 ver; // SENDER'S IKEYS INDEX BEING REGISTERED
        u8 _ [7];
    }; u64 w[(K_LEN * K_WORDS) + 1];
};

BUILD_ASSERT(sizeof(ping_s) == PING_SIZE);
