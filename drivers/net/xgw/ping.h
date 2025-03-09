
// KEYS                     SENDER'S IKEYS BEING TAUGHT (UNDEFINED ON PONG)
// RANDOM | VER             SENDER'S IKEYS INDEX BEING REGISTERED (UNDEFINED ON PONG)
// TIME                     SENDER'S TIME (RAW)
#define PING_SIZE 80

// KEYS, VERSION
#define PING_RANDOMS_N 9

struct ping_s {
    u64 rnd [K_LEN];
    u16 _;
    u16 ver;
    u16 __;
    u16 sec;
    u64 time;
};
