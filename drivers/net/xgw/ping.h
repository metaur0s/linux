
// KEYS                     SENDER'S IKEYS BEING TAUGHT (UNDEFINED ON PONG)
// RANDOM | VER             SENDER'S IKEYS INDEX BEING REGISTERED (UNDEFINED ON PONG)
// TIME                     SENDER'S TIME (RAW)
#define PING_SIZE 80

// KEYS, VERSION
#define PING_RANDOMS_N 9

struct ping_s {
    u64 rnd [K_LEN];
    u8 _[7];
    u8 ver;
    u64 time;
};
