
// !!!!!! TODO: XGW TO XGW REDIRECT WITHOUT GOING THROUGH IP STACK

static inline u64   swap64 (const u64 x) { const uint q = popcount64(x); return (x >> q) | (x << (64 - q)); }
static inline u64 unswap64 (const u64 x) { const uint q = popcount64(x); return (x << q) | (x >> (64 - q)); }

static inline u64   swap64q (const u64 x, const uint q) { return (x >> q) | (x << (64 - q)); }
static inline u64 unswap64q (const u64 x, const uint q) { return (x << q) | (x >> (64 - q)); }

#define   swap64x(x, y, z) (  swap64q((x), popcount64(z)) + (y))
#define unswap64x(x, y, z)  unswap64q((x) - (y), popcount64(z))

// USA SÓ METADE DAS VARIÁVEIS; AS DEMAIS SÃO USADAS PARA ROTACIONAR
// ASSIM UM BRUTE-FORCE VAI TER DE ALÉM DE CHECAR TODAS AS POSSIBILIDADES DISSO AQUI, MAS TAMBÉM AS ROTACIONAIS
#define ENC(x)    swap64x(  swap64x(  swap64x(  swap64x((x), A, B), C, D), E, F), G, H)
#define DEC(x)  unswap64x(unswap64x(unswap64x(unswap64x((x), G, H), E, F), C, D), A, B)

static inline void __crypt_fetch_data (const u64* const pos, const u64* const end) {

#if 1
    // NOTE: CHOOSE THE RIGHT ONE HERE
#define ___prefetch __prefetch_w_temporal_high
    ___prefetch((void*)pos +  0*CACHE_LINE_SIZE);
    ___prefetch((void*)pos +  1*CACHE_LINE_SIZE);
    ___prefetch((void*)pos +  2*CACHE_LINE_SIZE);
    ___prefetch((void*)pos +  3*CACHE_LINE_SIZE);
    ___prefetch((void*)pos +  4*CACHE_LINE_SIZE);
    ___prefetch((void*)pos +  5*CACHE_LINE_SIZE);
    ___prefetch((void*)pos +  6*CACHE_LINE_SIZE);
    ___prefetch((void*)pos +  7*CACHE_LINE_SIZE);
#if 0
    ___prefetch((void*)pos +  8*CACHE_LINE_SIZE);
    ___prefetch((void*)pos +  9*CACHE_LINE_SIZE);
    ___prefetch((void*)pos + 10*CACHE_LINE_SIZE);
    ___prefetch((void*)pos + 11*CACHE_LINE_SIZE);
    ___prefetch((void*)pos + 12*CACHE_LINE_SIZE);
    ___prefetch((void*)pos + 13*CACHE_LINE_SIZE);
    ___prefetch((void*)pos + 14*CACHE_LINE_SIZE);
    ___prefetch((void*)pos + 15*CACHE_LINE_SIZE);
#endif
#undef ___prefetch
    (void)end;
#else
    (void)pos;
    (void)end;
#endif
}

u64 encrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, u64 x, const u64 sign) {

    ASSERT(end >= &pos[PKT_ALIGN_SIZE]);
    ASSERT(end <= &pos[PKT_ALIGN_SIZE + XGW_PAYLOAD_MAX]);

    __crypt_fetch_data(pos, end);

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    loop {

        // AVALANCHE OF ORIGINAL THROUGH KEYS
        // DONT LET THE ORIGINAL CONTROL THE ACCUMULATION AND LOOP
        // E FAZ O A AFETAR O H, ETC
        x += A + B + C + D + E + F + G + H;

        do {

            // RANDOMLY ADD THE PREVIOUS ORIG AND ALL THE KEYS
            A += B += C += D += E += F += G += H += x;

            // RANDOMLY ADD OUR CONSTANTS
            A += K[H % K_LEN];
            B += K[G % K_LEN];
            C += K[F % K_LEN];
            D += K[E % K_LEN];
            E += K[D % K_LEN];
            F += K[C % K_LEN];
            G += K[B % K_LEN];
            H += K[A % K_LEN];

            // THIS HAS 2 EFFECTS:
            //      1 - RANDOMIZES THE AMOUNT OF LOOP ITERATIONS
            //      2 - RANDOMIZES THE VALUE OF X FOR THE SUM ABOVE
            // MAX: 64 / (24 +    0) = 2.66
            // AVG: 64 / (24 + 32/2) = 1.6
            // MIN: 64 / (24 +   32) = 1.14
        } while (x >>= (24 + (x % 32)));

        if (pos == end)
            // USE THE ORIGINAL SIGN
            x = sign;
        else // READ THE ORIGINAL VALUE
            x = BE64(*pos);

        // ENCRYPT IT
        const u64 e = ENC(x);

        if (pos == end)
            // RETURN THE ENCRYPTED SIGN
            return e;

        // WRITE THE ENCRYPTED VALUE
        *pos++ = BE64(e);
    }
}

u64 decrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, u64 x, const u64 hash) {

    ASSERT(end >= &pos[PKT_ALIGN_SIZE]);
    ASSERT(end <= &pos[PKT_ALIGN_SIZE + XGW_PAYLOAD_MAX]);

    __crypt_fetch_data(pos, end);

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    loop {

        // AVALANCHE OF ORIGINAL THROUGH KEYS
        x += A + B + C + D + E + F + G + H;

        do {

            // RANDOMLY ADD THE PREVIOUS ORIG AND ALL THE KEYS
            A += B += C += D += E += F += G += H += x;

            // RANDOMLY ADD OUR CONSTANTS
            A += K[H % K_LEN];
            B += K[G % K_LEN];
            C += K[F % K_LEN];
            D += K[E % K_LEN];
            E += K[D % K_LEN];
            F += K[C % K_LEN];
            G += K[B % K_LEN];
            H += K[A % K_LEN];

        } while (x >>= (24 + (x % 32)));

        if (pos == end)
            // USE THE ENCRYPTED SIGN
            x = hash;
        else // READ THE ENCRYPTED VALUE
            x = BE64(*pos);

        // DECRYPT IT
        x = DEC(x);

        if (pos == end)
            // RETURN THE ORIGINAL SIGN
            return x;

        // WRITE THE ORIGINAL VALUE
        *pos++ = BE64(x);
    }
}

// USING SECRET S, APPLY RANDOM R, AND DERIVE KEY K
static void secret_derivate_random_as_key (const u64 S[SECRET_KEYS_N][K_LEN], const u64 L[K_LEN], const u64 R[K_LEN], u64 K[K_LEN]) {

    u64 sum = 0;

    // WHILE IS FETCHING L...
    __prefetch_r_temporal_high(L);

    // ...LOAD DYNAMIC RANDOM
    for_count (k, K_LEN)
        K[k] = sum += BE64(R[k]);

    // ...AND NOW APPLY L
    for_count (k, K_LEN)
        K[k] += sum += L[k];

    // THE INDEXING WILL CONSIDER ALL THE BITS
    sum += sum >> 32;
    sum += sum >> 16;

    // DYNAMICALLY CHOOSE CONSTANT SECRET
    const u64* const restrict s = S[sum % SECRET_KEYS_N];

    // WHILE IS FETCHING S...
    __prefetch_r_temporal_high(s);

    // ...DO THIS (THIS IS DUMB, BUT WE ARE STALLED ANYWAY)
    // [(i, 7 - i)  for i in range(8)] -> [(0, 7), (1, 6), (2, 5), (3, 4), (4, 3), (5, 2), (6, 1), (7, 0)]
    for_count (k, K_LEN)
        K[k] += sum += K[7 - k];

    // ...AND NOW APPLY S
    for_count (k, K_LEN)
        K[k] += sum += s[k];
}

// GENERATE CONSTANT PING/PONG KEYS
// REFAZER ISSO AO ALTERAR:
//  -- SELF ID
//  -- NODE ID
//  -- SECRET (PASSWORD)
// * MUST NOT EXPOSE SECRET.
// * MUST PROVE SENDER/RECEIVER HOST IDS.
// * MUST PROVE THE PING WILL GENERATE THE SAME KEYS.
// * CONSIDERING WE MAY HAVE THOUSANDS OF HOSTS USING THE SAME PASSWORD, MUST NOT BE ABLE TO WATCH ALL AND DISCOVER IT
// --
// WILL GENERATE TWO KEYS:
//      NODE HIGHER WILL USE THEM AS IN/OUT,
//      NODE LOWER WILL USE THEM AS OUT/IN
static void reset_node_ping_keys (node_s* const node, const uint self, const uint peer) {

    ASSERT(self < NODES_N);
    ASSERT(peer < NODES_N);
    ASSERT(self != peer);

    u64* restrict XK; u64 x = 0x0001000100010001ULL * self;
    u64* restrict YK; u64 y = 0x0001000100010001ULL * peer;
    u64* restrict LK;

    if (x > y) {
        // SWAP THEM, SO WE ALWAYS HAVE THE SAME X AND Y
        x ^= y; y ^= x; x ^= y;
        // CADA LADO USA OS MESMOS PING/PONG, POREM INVERTIDOS
        XK = node->iKeys[I_KEY_PING];
        YK = node->oKeys[O_KEY_PING];
    } else {
        XK = node->oKeys[O_KEY_PING];
        YK = node->iKeys[I_KEY_PING];
    }   LK = node->lKey;

    // INITIALIZE THE KEYS
    // MESMO QUE USE O MESMO PASSWORD ENTRE VARIOS NODES, NAO DEIXA QUE O PING KEYS SEJA O MESMO
    for_count (k, K_LEN) XK[k] = x;
    for_count (k, K_LEN) YK[k] = y;
    for_count (k, K_LEN) LK[k] = x + y;

    // NOW MERGE WITH THE ENTIRE SECRET
    for_count (s, SECRET_KEYS_N) {
        for_count (k, K_LEN) x += XK[k] += swap64q(node->secret[s][k], popcount(x));
        for_count (k, K_LEN) y += YK[k] += swap64q(node->secret[s][k], popcount(y));
        for_count (k, K_LEN)      LK[k] += swap64q(node->secret[s][k], popcount(x + y));
    }

    //
    for_count (pid, PATHS_N) {

        // O CLIENTE VAI MANDAR CADA SYN COM ESTE DCOUNTER
        // O SERVER VAI RECEVER O SYN COM ESTE DCOUNTER
        node->synCounters[pid] = x;

        if (1) {
            // THE PATH IS USING THE DEFAULT SYN COUNTER
            // TODO: NO FUTURO, PERMITIR O USUARIO SETAR ISSO
            // ENTAO ACIMA COLOCA NUMA ARRAY synCountersAuto
            // E AQUI COPIA PARA o synCounters
            //
            // TODO: ISSO É AO ATIVAR O PATH
            node->paths[pid].counterSyn = x;
        }

        x += y += swap64q(x, popcount(y));
    }
}

// REPETE ELE ATE PREENCHER TODA A ARRAY
static void copy_and_fill (void* restrict dst, const uint dstSize, const void* const restrict src, uint srcSize) {

    ASSERT(dstSize >= srcSize);

    // COPY FROM THE ORIGINAL BUFFER, THE ORIGINAL SIZE
    memcpy(dst, src, srcSize);

    // RECOPY FROM ITSELF, ITSELF'S SIZE
    uint chunk;

    while ((chunk = dstSize - srcSize)) {
        if (chunk > srcSize)
            chunk = srcSize;
        memcpy(dst + srcSize, dst, chunk);
        srcSize += chunk;
    }
}

// TODO: COLD FUNCTION
static void secret_derivate_from_password (u64 S[SECRET_KEYS_N][K_LEN], const u8* const restrict password, const uint size) {

    ASSERT(size >= PASSWORD_SIZE_MIN);
    ASSERT(size <= PASSWORD_SIZE_MAX);
    ASSERT(PASSWORD_SIZE_MAX <= SECRET_SIZE);

    copy_and_fill(S, SECRET_SIZE, password, size);

#ifndef __BIG_ENDIAN
    // EM LOCAL ENDIAN
    for_count (s, SECRET_KEYS_N)
        for_count (k, K_LEN)
            S[s][k] =
       BE64(S[s][k]);
#endif

    //
    u64 A = S[0][0], B = S[0][1], C = S[0][2], D = S[0][3],
        E = S[0][4], F = S[0][5], G = S[0][6], H = S[0][7];

    // NAO DEIXA SER APENAS UMA REPETICAO
    for_count (s, SECRET_KEYS_N)
        for_count (k, K_LEN)
            A += B += C += D += E += F += G += H += S[s][k] =
                swap64(swap64(swap64(swap64(swap64(swap64(swap64(S[s][k] + H) + G) + F) + E) + D) + C) + B) + A;

    // SHUFFLE
    for_count (c, PASSWORD_ROUNDS) {
        for_count (s, SECRET_KEYS_N) {
            for_count (k, K_LEN) {

                A += S[H % SECRET_KEYS_N][C % K_LEN] * E;
                B += S[G % SECRET_KEYS_N][D % K_LEN] * F;
                C += S[F % SECRET_KEYS_N][E % K_LEN] * G;
                D += S[E % SECRET_KEYS_N][F % K_LEN] * H;
                E += S[D % SECRET_KEYS_N][G % K_LEN] * A;
                F += S[C % SECRET_KEYS_N][H % K_LEN] * B;
                G += S[B % SECRET_KEYS_N][A % K_LEN] * C;
                H += S[A % SECRET_KEYS_N][B % K_LEN] * D;

                S[s][k] = swap64(swap64(swap64(swap64(swap64(swap64(swap64(S[s][k] + H) + G) + F) + E) + D) + C) + B) + A;
            }
        }
    }
}

// AUTHENTICITY AND INTEGRITY
// - SRC HOST ID
// - DST HOST ID
// - PATH ID
// - RECEIVER IN SLOT
// - DATA SIZE
// AUTHENTICITY, INTEGRITY AND PRIVACY
// - DATA

// NOTE: QUALQUER ALTERAÇÃO EM UM BIT DO PATH ID OU DO RCOUNTER TEM QUE RESULTAR EM ALGO DIFERENTE AQUI
#define _PKT_SEED(pkt) BE64(pkt->x.info ^ pkt->x.counter)

// A IDÉIA É ASSUMIR QUE O SIZE É SEMPRE MULTIPLO DE 64-BITS.
// DAÍ O RESTO QUE PASSAR DISSO, É "EXPULSO" DO ALIGN, FAZENDO ELE COMECAR MAIS PARA FRENTE.
#define _PKT_START(pkt, size) (PTR(pkt) + PKT_SIZE + (size % sizeof(u64)))
#define _PKT_END(pkt, size)   (PTR(pkt) + PKT_SIZE + PKT_ALIGN_SIZE + size)

// NOTE: TEM QUE FAZER APOS TER SETADO O PKT INFO E RCOUNTER
#define pkt_encrypt(node, o, pkt, size, lcounter) encrypt(node->oKeys[o], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt), lcounter)
#define pkt_decrypt(node, i, pkt, size, lcounter) decrypt(node->iKeys[i], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt), lcounter)
