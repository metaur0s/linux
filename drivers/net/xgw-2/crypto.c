
// !!!!!! TODO: XGW TO XGW REDIRECT WITHOUT GOING THROUGH IP STACK

//
#define PKT_SEED(pkt) \
    BE64( (pkt)->x.info \
        ^ (pkt)->x.seed )

// QUANTAS PALAVRAS TEM, CONSIDERANDO INCOMPLETAS COMO INTEIRAS
#define PKT_Q(size) ((size) + sizeof(u64)) / sizeof(u64)
#define PKT_P(pkt, size) (PTR((pkt)->p) + (size) % sizeof(u64))

//
#define pkt_encrypt(node, o, pkt, size, rcounter) encrypt((node)->oKeys[o], PKT_P(pkt, size), PKT_P(pkt, size) + PKT_Q(size), PKT_SEED(pkt), (rcounter))
#define pkt_decrypt(node, i, pkt, size)           decrypt((node)->iKeys[i], PKT_P(pkt, size), PKT_P(pkt, size) + PKT_Q(size), PKT_SEED(pkt), BE64((pkt)->x.sign))

// AUTHENTICITY AND INTEGRITY
// - HOST IDS
// - PATH ID
// - LEARN IN/OUT SLOT
// AUTHENTICITY, INTEGRITY AND PRIVACY
// - DATA

// NAO FAZ UM SWAP FINAL POIS O VALOR É EXPOSTO K[4] ISSO SERIA INUTIL
#define ENC(x) (  swap64(  swap64(  swap64(  swap64(  swap64(  swap64(  swap64((x) + K[0][0]) + K[0][1]) + K[0][2]) + K[0][3]) + K[0][4]) + K[0][5]) + K[0][6]) + K[0][7])
#define DEC(x) (unswap64(unswap64(unswap64(unswap64(unswap64(unswap64(unswap64((x) - K[0][7]) - K[0][6]) - K[0][5]) - K[0][4]) - K[0][3]) - K[0][2]) - K[0][1]) - K[0][0])

static inline u64 encrypt (const u64x8 _K[K_LEN], u64* restrict ptr, u64* restrict const lmt, u64 x, const u64 sign) {

    // INITIAL KEYS, PER INTERVAL
    u64x8 K[K_LEN] = { _K[0], _K[1], _K[2], _K[3], _K[4], _K[5], _K[6], _K[7] };

    loop {

        // AVALANCHE OF X THROUGH KEYS
        K[7] += K[6] += K[5] += K[4] += K[3] += K[2] += K[1] += K[0] += x;
        K[0] += K[6] += K[2] += K[4] += K[7] += K[3] += K[1] += K[5];

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
    }
}

static inline u64 decrypt (const u64x8 _K[K_LEN], u64* restrict ptr, u64* restrict const lmt, u64 x, const u64 sign) {

    // INITIAL KEYS, PER INTERVAL
    u64x8 K[K_LEN] = { _K[0], _K[1], _K[2], _K[3], _K[4], _K[5], _K[6], _K[7] };

    loop {

        // AVALANCHE OF X THROUGH KEYS
        K[7] += K[6] += K[5] += K[4] += K[3] += K[2] += K[1] += K[0] += x;
        K[0] += K[6] += K[2] += K[4] += K[7] += K[3] += K[1] += K[5];

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
    }
}

// MUST NOT EXPOSE SECRETS
static noinline void learn (const node_s* const node, const u64 ping[K_LEN][8], u64x8 K[K_LEN]) {

    u64x8 v = { 0, 0, 0, 0, 0, 0, 0, 0 };

    // DINAMICO ALEATORIO
    for_count (k, K_LEN) {
        for_count (w, 8)
            v[w] += BE64(ping[k][w]);
        K[k] = v;
    }

    // REDUCE IT TO A SINGLE WORD
    u64 s = v[0] + v[1] + v[2] + v[3] +
            v[4] + v[5] + v[6] + v[7];

    // HASH IT AS AN INDEX
    s += s >> 32;
    s += s >> 16;
    s %= SECRET_PAIRS_N;

    // CONSTANTE, DINAMICAMENTE ESCOLHIDO
    const u64x8* const restrict S = node->secret[s];

    for_count (k, K_LEN)
        K[k] += S[k];
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
    u64x8 y = node->secret[2][1] * (self > peer ? peer : self);

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

    // NAO DEIXA SER APENAS UMA REPETICAO
    for_count (p, SECRET_PAIRS_N)
        for_count (k, K_LEN)
            node->secret[p][k] +=
           (node->secret[p][k] * p) ^
           (node->secret[p][k] * k);

    u64x8 x = node->secret[0][0];

    for_count (c, PASSWORD_ROUNDS) {
        for_count (p, SECRET_PAIRS_N) {
            for_count (k, K_LEN) {

                x += node->secret[x[7] % SECRET_PAIRS_N][x[3] % K_LEN] * x[0];
                x += node->secret[x[6] % SECRET_PAIRS_N][x[1] % K_LEN] * x[1];
                x += node->secret[x[5] % SECRET_PAIRS_N][x[0] % K_LEN] * x[2];
                x += node->secret[x[4] % SECRET_PAIRS_N][x[2] % K_LEN] * x[3];
                x += node->secret[x[3] % SECRET_PAIRS_N][x[7] % K_LEN] * x[4];
                x += node->secret[x[2] % SECRET_PAIRS_N][x[4] % K_LEN] * x[5];
                x += node->secret[x[1] % SECRET_PAIRS_N][x[5] % K_LEN] * x[6];
                x += node->secret[x[0] % SECRET_PAIRS_N][x[6] % K_LEN] * x[7];

                node->secret[p][k] = x;
            }
        }
    }
}
