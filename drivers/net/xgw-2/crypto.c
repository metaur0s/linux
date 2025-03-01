
// !!!!!! TODO: XGW TO XGW REDIRECT WITHOUT GOING THROUGH IP STACK

// QUANTAS PALAVRAS TEM, CONSIDERANDO INCOMPLETAS COMO INTEIRAS
#define PKT_Q(size) ((size) + sizeof(u64)) / sizeof(u64)
#define PKT_P(pkt, size) (PTR((pkt)->p) + (size) % sizeof(u64))

//
#define PKT_SEED(pkt) \
    BE64( (pkt)->x.info \
        ^ (pkt)->x.seed )

//
#define pkt_encrypt(node, o, pkt, size, rcounter) encrypt((node)->oKeys[o], PKT_P(pkt, size), PKT_Q(size), PKT_SEED(pkt), (rcounter))
#define pkt_decrypt(node, i, pkt, size)           decrypt((node)->iKeys[i], PKT_P(pkt, size), PKT_Q(size), PKT_SEED(pkt), BE64((pkt)->x.sign))

// AUTHENTICITY AND INTEGRITY
// - HOST IDS
// - PATH ID
// - LEARN IN/OUT SLOT
// AUTHENTICITY, INTEGRITY AND PRIVACY
// - DATA

#define A k[0]
#define B k[1]
#define C k[2]
#define D k[3]
#define E k[4]
#define F k[5]
#define G k[6]
#define H k[7]

// NAO FAZ UM SWAP FINAL POIS O VALOR É EXPOSTO E ISSO SERIA INUTIL
#define ENC(x) (  swap64(  swap64(  swap64(  swap64(  swap64(  swap64(  swap64((x) + A[0]) + A[1]) + A[2]) + A[3]) + A[4]) + A[5]) + A[6]) + A[7])
#define DEC(x) (unswap64(unswap64(unswap64(unswap64(unswap64(unswap64(unswap64((x) - A[7]) - A[6]) - A[5]) - A[4]) - A[3]) - A[2]) - A[1]) - A[0])

static inline u64 encrypt (const u64x8 K[K_LEN], u64* restrict ptr, u64* restrict const lmt, const u64 sign) {

    // INITIAL KEYS, PER INTERVAL
    u64x8 k[K_LEN] = { K[0], K[1], K[2], K[3], K[4], K[5], K[6], K[7] };

    loop {

        u64 x;

        if (ptr != lmt)
            // READ THE ORIGINAL VALUE
            x = BE64(*ptr);
        else // USE THE ORIGINAL SIGN
            x = sign;

        // ENCRYPT
        const u64 e = ENC(x);

        if (ptr == lmt)
            // RETURN THE ENCRYPTED SIGN
            return e;

        // WRITE THE ENCRYPTED VALUE
        *ptr++ = BE64(e);

        // AVALANCHE OF X THROUGH KEYS
        H += G += F += E += D += C += B += A += x;
        A ^= G ^= C ^= E ^= H ^= D ^= B ^= F;
    }
}

static inline u64 decrypt (const u64x8 K[K_LEN], u64* restrict ptr, u64* restrict const lmt, const u64 sign) {

    // INITIAL KEYS, PER INTERVAL
    u64x8 k[8] = { K[0], K[1], K[2], K[3], K[4], K[5], K[6], K[7] };

    loop {

        u64 x;

        if (ptr != lmt)
            // READ THE ENCRYPTED VALUE
            x = BE64(*ptr);
        else // USE THE ENCRYPTED SIGN
            x = sign;

        // DECRYPT
        x = DEC(x);

        if (ptr == lmt)
            // RETURN THE ORIGINAL SIGN
            return x;

        // WRITE THE ORIGINAL VALUE
        *ptr++ = BE64(x);

        // AVALANCHE OF X THROUGH KEYS
        H += G += F += E += D += C += B += A += x;
        A ^= G ^= C ^= E ^= H ^= D ^= B ^= F;
    }
}

// MUST NOT EXPOSE KEYS
static noinline void learn (const node_s* const node, const u64 ping[K_LEN * 8], u64x8 K[K_LEN]) {

    // DINAMICO ALEATORIO
    for_count (i, K_LEN)
        for_count (ii, 8)
            K[i][ii] = BE64(ping[i*K_LEN + ii]);

    // CONSTANTE, DINAMICAMENTE ESCOLHIDO
    const u64x8* const restrict S = node->secret[__u64x8_sum_reduced(K, K_LEN) % SECRET_PAIRS_N];

    for_count (i, K_LEN)
        K[i] += S[i];
}

// CONSTANT KEYS, FOR PING/PONG
// TODO: SO REFAZER ISSO SE TIVER MUDADO O SECRET (BY PASSWORD), O NODE ID OU O SELF ID
// TODO: COLD FUNCTION
// MUST PROVE THE PING WILL GENERATE THE SAME KEYS
static noinline void reset_node_ping_keys (node_s* const node, const uint self, const uint peer) {

    ASSERT(self < NODES_N);
    ASSERT(peer < NODES_N);
    ASSERT(self != peer);

    u64x8* restrict Kx;
    u64x8* restrict Ky;

    // CADA LADO USA UM PAR
    if (self > peer) {
        Kx = node->oKeys[O_PAIR_PING];
        Ky = node->iKeys[I_PAIR_PING];
    } else {
        Ky = node->oKeys[O_PAIR_PING];
        Kx = node->iKeys[I_PAIR_PING];
    }

    //
    memcpy(Kx, node->secret[0], sizeof(node->secret[0]));
    memcpy(Ky, node->secret[1], sizeof(node->secret[1]));

    // MESMO QUE USE O MESMO PASSWORD ENTRE VARIOS NODES, NAO DEIXA QUE O PING KEYS SEJA O MESMO
    u64x8 x = node->secret[2][0] * (self > peer ? self : peer);
    u64x8 y = node->secret[2][1] * (self > peer ? self : peer);

    //
    for_count (s, SECRET_PAIRS_N) {
        for_count (k, K_LEN) {
            x += Kx[s % K_LEN] += x * node->secret[s][k];
            y += Ky[s % K_LEN] += y * node->secret[s][k];
        }
    }
}

// TODO: COLD FUNCTION
static noinline void secret_derivate (node_s* const node, const u8* const restrict password, uint size) {

    ASSERT(size >= PASSWORD_SIZE_MIN);
    ASSERT(size <= PASSWORD_SIZE_MAX);
    ASSERT(PASSWORD_SIZE_MAX <= sizeof(node->secret));

    // REPETE ELE ATE PREENCHER TODA A ARRAY
    memcpy(node->secret, password, size);

    do { uint chunk = sizeof(node->secret) - size;
        if (chunk > size)
            chunk = size;
        memcpy(PTR(node->secret) + size, node->secret, chunk);
        size += chunk;
    } while (size != sizeof(node->secret));

#if 1
    // EM LOCAL ENDIAN
    for_count (p, SECRET_PAIRS_N)
        for_count (k, K_LEN)
            for_count (w, 8)
                node->secret[p][k][w]
         = BE64(node->secret[p][k][w]);
#endif

    u64x8 x = {
        0x5F72D0422FE2CB94ULL, 0x404B238BAAB7F569ULL, 0x8BC0A61857A6C9A6ULL, 0x0189D9EA53018DB2ULL,
        0x44D023C1E7FB2EAEULL, 0xD23789A7CBB074ABULL, 0x815583AD150B4C6AULL, 0x56F755173318EF82ULL
    };

    // NAO DEIXA SER APENAS UMA REPETICAO
    // any(print('0x%016X' % ((0x815583AD150B4C6A * p + 0x5F72D0422FE2CB94  * k) & ((1 << 64) - 1))) for p in range(16) for k in range(KEYS_N))
    for_count (p, SECRET_PAIRS_N)
        for_count (k, K_LEN)
            x += node->secret[p][k] += p*x + k*x;

    // SECRET
    for_count (c, PASSWORD_ROUNDS) {
        for_count (p, SECRET_PAIRS_N) {
            for_count (k, K_LEN) {

                x += node->secret[x[7] % SECRET_PAIRS_N][x[3] % KEYS_N] * x[0];
                x += node->secret[x[6] % SECRET_PAIRS_N][x[1] % KEYS_N] * x[1];
                x += node->secret[x[5] % SECRET_PAIRS_N][x[0] % KEYS_N] * x[2];
                x += node->secret[x[4] % SECRET_PAIRS_N][x[2] % KEYS_N] * x[3];
                x += node->secret[x[3] % SECRET_PAIRS_N][x[7] % KEYS_N] * x[4];
                x += node->secret[x[2] % SECRET_PAIRS_N][x[4] % KEYS_N] * x[5];
                x += node->secret[x[1] % SECRET_PAIRS_N][x[5] % KEYS_N] * x[6];
                x += node->secret[x[0] % SECRET_PAIRS_N][x[6] % KEYS_N] * x[7];

                node->secret[p][k] = x;
            }
        }
    }
}
