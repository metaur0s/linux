
// !!!!!! TODO: XGW TO XGW REDIRECT WITHOUT GOING THROUGH IP STACK

// TODO: TEM QUE SER TUDO += E SEM ESTE ^=
#define __KEYS_ITER(x) { \
        A ^= B += C ^= D += E ^= F += G ^= H += ((x) + ITER_X_ADD) ^ ITER_X_MASK; \
        A += ((ITER_KEY_ADD_0 + H) * popcount(B) + F) * popcount(E); \
        B += ((ITER_KEY_ADD_1 + G) * popcount(C) + D) * popcount(C); \
        C += ((ITER_KEY_ADD_2 + F) * popcount(D) + B) * popcount(H); \
        D += ((ITER_KEY_ADD_3 + E) * popcount(E) + A) * popcount(G); \
        E += ((ITER_KEY_ADD_4 + D) * popcount(F) + G) * popcount(A); \
        F += ((ITER_KEY_ADD_5 + C) * popcount(G) + H) * popcount(B); \
        G += ((ITER_KEY_ADD_6 + B) * popcount(H) + C) * popcount(D); \
        H += ((ITER_KEY_ADD_7 + A) * popcount(A) + E) * popcount(F); \
    }

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
    u64x8 x = node->secret[2][0] * self;
    u64x8 y = node->secret[2][1] * peer;

    //
    for_count (s, SECRET_PAIRS_N) {
        for_count (i, K_LEN) {
            x = Kx[s % K_LEN] += x * node->secret[s][i];
            y = Ky[s % K_LEN] += y * node->secret[s][i];
        }
    }
}

// TODO: COLD FUNCTION
static noinline void secret_derivate (node_s* const node, const u8* const restrict password, uint size) {

    ASSERT(size >= PASSWORD_SIZE_MIN);
    ASSERT(size <= PASSWORD_SIZE_MAX);
    ASSERT(PASSWORD_SIZE_MAX <= SECRET_SIZE);

    //
    memcpy(node->secret, password, size);

    // REPETE ELE ATE PREENCHER TODA A ARRAY
    do { uint chunk = SECRET_SIZE - size;
        if (chunk > size)
            chunk = size;
        memcpy(PTR(node->secret) + size, node->secret, chunk);
        size += chunk;
    } while (size != SECRET_SIZE);

#if 1
    // EM LOCAL ENDIAN
    for_count (p, SECRET_PAIRS_N)
        for_count (k, KEYS_N)
                node->secret[p][k] =
           BE64(node->secret[p][k]);
#endif

    // NAO DEIXA SER APENAS UMA REPETICAO
    // any(print('0x%016X' % ((0x815583AD150B4C6A * p + 0x5F72D0422FE2CB94  * k) & ((1 << 64) - 1))) for p in range(16) for k in range(KEYS_N))
    for_count (p, SECRET_PAIRS_N)
        for_count (k, KEYS_N)
            node->secret[p][k] += 0x815583AD150B4C6AULL * p
                                + 0x5F72D0422FE2CB94ULL * k;

    // SECRET
    u64 A = 0x5F72D0422FE2CB94ULL, B = 0x404B238BAAB7F569ULL, C = 0x8BC0A61857A6C9A6ULL, D = 0x0189D9EA53018DB2ULL,
        E = 0x44D023C1E7FB2EAEULL, F = 0xD23789A7CBB074ABULL, G = 0x815583AD150B4C6AULL, H = 0x56F755173318EF82ULL;

    for_count (c, PASSWORD_ROUNDS) {
        for_count (p, SECRET_PAIRS_N) {
            for_count (k, KEYS_N) {

                A += node->secret[H % SECRET_PAIRS_N][popcount(F) % KEYS_N] * popcount(G);
                B += node->secret[G % SECRET_PAIRS_N][popcount(E) % KEYS_N] * popcount(H);
                C += node->secret[F % SECRET_PAIRS_N][popcount(D) % KEYS_N] * popcount(A);
                D += node->secret[E % SECRET_PAIRS_N][popcount(C) % KEYS_N] * popcount(B);
                E += node->secret[D % SECRET_PAIRS_N][popcount(B) % KEYS_N] * popcount(C);
                F += node->secret[C % SECRET_PAIRS_N][popcount(A) % KEYS_N] * popcount(D);
                G += node->secret[B % SECRET_PAIRS_N][popcount(H) % KEYS_N] * popcount(E);
                H += node->secret[A % SECRET_PAIRS_N][popcount(G) % KEYS_N] * popcount(F);

                node->secret[p][k] = enc64(node->secret[p][k]);
            }
        }
    }
}
