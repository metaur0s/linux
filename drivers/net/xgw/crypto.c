
// !!!!!! TODO: XGW TO XGW REDIRECT WITHOUT GOING THROUGH IP STACK

// NAO FAZ UM SWAP FINAL POIS O VALOR É EXPOSTO K[4] ISSO SERIA INUTIL
#define ENC(x) (  swap64(  swap64(  swap64(  swap64(  swap64(  swap64(  swap64((x) + A) + B) + C) + D) + E) + F) + G) + H)
#define DEC(x) (unswap64(unswap64(unswap64(unswap64(unswap64(unswap64(unswap64((x) - H) - G) - F) - E) - D) - C) - B) - A)

static inline u64 encrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, u64 x) {

    ASSERT(end >= &pos[PKT_ALIGN_SIZE]);
    ASSERT(end <= &pos[PKT_ALIGN_SIZE + XGW_PAYLOAD_MAX]);

    __prefetch_w_temporal_none(pos);

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    loop {

        // AVALANCHE OF ORIGINAL THROUGH KEYS
        // DONT LET THE ORIGINAL CONTROL THE ACCUMULATION AND LOOP
        // E FAZ O A AFETAR O H, ETC
        x += ((((((A + B) ^ C) + D) ^ E) + F) ^ G) + H;

        do { // LOOPA DE 1 A 3 VEZES (A MAIORIA 2, AS VEZES 3, DIFICILMENTE 1)
            // (POIS É MAIS FÁCIL TER UM NO FIM DO QUE NENHUM NO MEIO E FIM)

            A += B += C += D += E += F += G += H += x;

            A += K[H % K_LEN];
            B += K[G % K_LEN];
            C += K[F % K_LEN];
            D += K[E % K_LEN];
            E += K[D % K_LEN];
            F += K[C % K_LEN];
            G += K[B % K_LEN];
            H += K[A % K_LEN];

            // MAX: 64 / (24 + (0 * 8)/8) = 2.66
            // AVG: 64 / (24 + (4 * 8)/8) = 2.28
            // MIN: 64 / (24 + (8 * 8)/8) = 2
        } while (x >>= (24 + (x % 8)));

        // IF FINISHED, RETURN THE HASH
        if (pos == end)
            return A + B + C + D + E + F + G + H;

        // READ THE ORIGINAL VALUE
        x = BE64(*pos);

        // WRITE THE ENCRYPTED VALUE
        *pos++ = BE64(ENC(x));
    }
}

static inline u64 decrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end) {

    ASSERT(end >= &pos[PKT_ALIGN_SIZE]);
    ASSERT(end <= &pos[PKT_ALIGN_SIZE + XGW_PAYLOAD_MAX]);

    __prefetch_w_temporal_none(pos);

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    loop {

        // AVALANCHE OF ORIGINAL THROUGH KEYS
        // DONT LET THE ORIGINAL CONTROL THE ACCUMULATION AND LOOP
        // E FAZ O A AFETAR O H, ETC
        x += ((((((A + B) ^ C) + D) ^ E) + F) ^ G) + H;

        do { // LOOPA DE 1 A 3 VEZES (A MAIORIA 2, AS VEZES 3, DIFICILMENTE 1)
            // (POIS É MAIS FÁCIL TER UM NO FIM DO QUE NENHUM NO MEIO E FIM)

            A += B += C += D += E += F += G += H += x;

            A += K[H % K_LEN];
            B += K[G % K_LEN];
            C += K[F % K_LEN];
            D += K[E % K_LEN];
            E += K[D % K_LEN];
            F += K[C % K_LEN];
            G += K[B % K_LEN];
            H += K[A % K_LEN];

            // MAX: 64 / (24 + (0 * 8)/8) = 2.66
            // AVG: 64 / (24 + (4 * 8)/8) = 2.28
            // MIN: 64 / (24 + (8 * 8)/8) = 2
        } while (x >>= (24 + (x % 8)));

        // IF FINISHED, RETURN THE HASH
        if (pos == end)
            return A + B + C + D + E + F + G + H;

        // READ THE ENCRYPTED VALUE AND DECRYPT IT
        x = DEC(BE64(*pos));

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
    // NOW WE HAVE
    for_count (k, K_LEN)
        K[k] += sum += K[k];

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
    for_count (k, K_LEN) XK[k] = x += 0xA601E857DF7F6A12ULL;
    for_count (k, K_LEN) YK[k] = y += 0xF0778A61A03B4480ULL;
    for_count (k, K_LEN) LK[k] = x + y;

    // NOW MERGE WITH THE ENTIRE SECRET
    u64 A = 0xAFEE0C56092DF220ULL, B = 0x8BD98EC995251C3CULL, C = 0x9A3943E82D8DD4D2ULL, D = 0x501FBD1644159395ULL,
        E = 0x02E12A80B229ADF5ULL, F = 0x52DC3014C0C6A1BAULL, G = 0x89DEA1B4941E360CULL, H = 0xC1B7B1DD4CA86D42ULL;

    const u64* S   =  node->secret;
    const u64* end = &node->secret[SECRET_KEYS_N];

    do { __crypt_prefetch_k_once(S);

        for_count (k, K_LEN) A += B += C += D += E += F += G += H += XK[k] = swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(XK[k] + S[k]) + H) + G) + F) + E) + D) + C) + B) + A);
        for_count (k, K_LEN) A += B += C += D += E += F += G += H += YK[k] = swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(YK[k] + S[k]) + H) + G) + F) + E) + D) + C) + B) + A);
        for_count (k, K_LEN) A += B += C += D += E += F += G += H +=  L[k] = swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(LK[k] + S[k]) + H) + G) + F) + E) + D) + C) + B) + A);

    } while ((S += K_LEN) != end);
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
    u64 A = 0x47092E83C59147FBULL, B = 0x6B80F1DD47505E84ULL, C = 0x8ACB8D82EBE013B0ULL, D = 0xEF7D87567DABC6DDULL,
        E = 0x879E9AF60BA2284DULL, F = 0x16CC54BBE05DA85FULL, G = 0x76A45CC8348064B5ULL, H = 0x03781F048D90B044ULL;

    // NAO DEIXA SER APENAS UMA REPETICAO
    for_count (s, SECRET_KEYS_N)
        for_count (k, K_LEN)
            A += B += C += D += E += F += G += H += S[s][k] =
                swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(S[s][k] + H) + G) + F) + E) + D) + C) + B) + A);

    // SHUFFLE
    for_count (c, PASSWORD_ROUNDS) {
        for_count (s, SECRET_KEYS_N) { __crypt_prefetch_k_once(S[s]);
            for_count (k, K_LEN) {

                A += S[H % SECRET_KEYS_N][C % K_LEN] * E;
                B += S[G % SECRET_KEYS_N][D % K_LEN] * F;
                C += S[F % SECRET_KEYS_N][E % K_LEN] * G;
                D += S[E % SECRET_KEYS_N][F % K_LEN] * H;
                E += S[D % SECRET_KEYS_N][G % K_LEN] * A;
                F += S[C % SECRET_KEYS_N][H % K_LEN] * B;
                G += S[B % SECRET_KEYS_N][A % K_LEN] * C;
                H += S[A % SECRET_KEYS_N][B % K_LEN] * D;

                S[s][k] = swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(S[s][k] + H) + G) + F) + E) + D) + C) + B) + A);
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

// A IDÉIA É ASSUMIR QUE O SIZE É SEMPRE MULTIPLO DE 64-BITS.
// DAÍ O RESTO QUE PASSAR DISSO, É "EXPULSO" DO ALIGN, FAZENDO ELE COMECAR MAIS PARA FRENTE.
static inline u64* _PKT_START (const pkt_s* const pkt, const uint size)
    { return PTR(pkt) + PKT_SIZE + (size % sizeof(pkt->p[0])); }

static inline u64* _PKT_END (const pkt_s* const pkt, const uint size)
    { return PTR(pkt) + PKT_SIZE + PKT_ALIGN_SIZE + size; }

// NOTE: TEM QUE FAZER APOS TER SETADO O PKT INFO E SCOUNTER
static inline u64 pkt_encrypt(const node_s* const node, const uint o, const pkt_s* const pkt, const uint size, const u64 dcounter)
    { return dcounter ^ encrypt(node->oKeys[o], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt)); }

static inline u64 pkt_decrypt(const node_s* const node, const uint i, const pkt_s* const pkt, const uint size, const u64 hash)
    { return hash     ^ decrypt(node->iKeys[i], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt)); }
