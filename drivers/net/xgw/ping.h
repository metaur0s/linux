
#define PING_SIZE 80
#define PONG_SIZE 72

#define PING_RANDOMS_N (K_LEN + 1)
#define PONG_RANDOMS_N 8

struct ping_s {
    u64 rnd [K_LEN];
    u8 _ [7];
    u8 ver; // SENDER'S IKEYS INDEX BEING REGISTERED
    u64 ctr; // THE SENDER'S LCOUNTER
};

struct pong_s {
    u64 rnd [PONG_RANDOMS_N];
    u64 ctr; // THE SENDER'S LCOUNTER
}; // NOTE: AO ENVIAR UM PONG, O PKT->COUNTER É O RCOUNTER SENDO RESPONDIDO

BUILD_ASSERT(sizeof(ping_s) == PING_SIZE);
BUILD_ASSERT(sizeof(pong_s) == PONG_SIZE);

BUILD_ASSERT(PING_SIZE != PONG_SIZE);
