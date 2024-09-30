
static inline u64   swap64 (const u64 x, const uint q) { return (x >> q) | (x << (64 - q)); }
static inline u64 unswap64 (const u64 x, const uint q) { return (x << q) | (x >> (64 - q)); }

static inline u64   _swap64 (const u64 x) { return   swap64(x, popcount(x)); }
static inline u64 _unswap64 (const u64 x) { return unswap64(x, popcount(x)); }

#define __KEYS_LOAD \
    u64 A = K[0], B = K[1], C = K[2], D = K[3], \
        E = K[4], F = K[5], G = K[6], H = K[7]

// NAO PRECISA PROTEGER TANTO
#define __KEYS_AVALANCHE(x) \
    H += G += F += E += \
    D += C += B += A += \
        ((((((((x) + A) ^ B) + C) ^ D) + E) ^ F) + G) ^ H

// - IMPEDIR QUE MESMO MONITORANDO CENTENAS DE MILHARES DE PACOTES,
//   POSSA DEDUZIR AS KEYS GERADAS PELO PAIR ATUAL
// ... DANDO O __KEYS_EVOLUTE NO SEED

// NAO PODE USAR O ENC64() POIS JA USOU AO ENCRIPTAR
// - MESMO QUE POR FORCA BRUTA QUEBRE UMA WORD,
//   PRECISARA DESCOBRIR MAIS KEYS PARA QUE QUEBRE OUTRAS
// - SE TENTAR FORCA BRUTA EM PALAVRAS SEQUENCIAIS, AUMENTARA A DIFICULDADE CADA VEZ MAIS
#define __KEYS_EVOLUTE \
    A += B += C += D += E += F += G += H += x; \
    A += ((H * popcount(B)) + F) * popcount(E); \
    B += ((G * popcount(C)) + D) * popcount(C); \
    C += ((F * popcount(D)) + B) * popcount(H); \
    D += ((E * popcount(E)) + A) * popcount(G); \
    E += ((D * popcount(F)) + G) * popcount(A); \
    F += ((C * popcount(G)) + H) * popcount(B); \
    G += ((B * popcount(H)) + C) * popcount(D); \
    H += ((A * popcount(A)) + E) * popcount(F)

// NESTE CASO NAO FAZ UM SWAP FINAL POIS O VALOR É EXPOSTO E ISSO SERIA INUTIL
#define enc64(x) (  _swap64(  _swap64(  _swap64(  _swap64(  _swap64(  _swap64(  _swap64((x) + A) + B) + C) + D) + E) + F) + G) + H)
#define dec64(x) (_unswap64(_unswap64(_unswap64(_unswap64(_unswap64(_unswap64(_unswap64((x) - H) - G) - F) - E) - D) - C) - B) - A)

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

static inline u64 encrypt (const u64 K[KEYS_N], u64* restrict ptr, uint q, u64 x, const u64 sign) {

    ASSERT(q >= (XGW_PAYLOAD_MIN / sizeof(u64)));
    ASSERT(q <= (XGW_PAYLOAD_MAX / sizeof(u64)));

    __KEYS_LOAD;

    loop { // ON THE FIRST ITER, X IS (INFO ^ SEED)

        // EVOLUTE THE KEYS
        __KEYS_EVOLUTE;

        if (q-- == 0)
            // RETURN THE ENCRYPTED SIGN
            return enc64(sign);

        // READ THE ORIGINAL
        x = BE64(*ptr);

        // WRITE THE ENCRYPTED
        *ptr++ = BE64(enc64(x));
    }
}

static inline u64 decrypt (const u64 K[KEYS_N], u64* restrict ptr, uint q, u64 x, const u64 sign) {

    ASSERT(q >= (XGW_PAYLOAD_MIN / sizeof(u64)));
    ASSERT(q <= (XGW_PAYLOAD_MAX / sizeof(u64)));

    __KEYS_LOAD;

    loop { // ON THE FIRST ITER, X IS (INFO ^ SEED)

        // EVOLUTE THE KEYS
        __KEYS_EVOLUTE;

        if (q-- == 0)
            // RETURN THE DECRYPTED SIGN
            return dec64(sign);

        // READ THE ENCRYPTED, AND DECRYPT IT
        x = dec64(BE64(*ptr));

        // WRITE THE ORIGINAL
        *ptr++ = BE64(x);
    }
}

// AUTHENTICITY
// MUST PROVE THE HOST IDS
// MUST PROVE THE PATH ID
// MUST PROVE THE PING INTEGRITY
// MUST PROVE THE PING AUTHENTICITY
// MUST PROVE THE PING WILL GENERATE THE SAME KEYS
// MUST PROVE THE LEARN IN SLOT
// MUST NOT EXPOSE KEYS
static noinline void learn (const node_s* const node, const u64 ping[PING_WORDS_N], u64 K[KEYS_N]) {

    // CONSTANTE
    u64 A = 0x05D171D85D80EBC4ULL, B = 0x9985E7AB107E8FCAULL, C = 0x263F3484D10AC084ULL, D = 0x47FDF736769A001AULL,
        E = 0xC6D8BC149729F1C4ULL, F = 0xC445BC1CB6B1BD4DULL, G = 0x96579857437F26A3ULL, H = 0x0780BABD0EF6CE16ULL;

    // DINAMICO ALEATORIO
    for_count (i, PING_WORDS_N)
        __KEYS_AVALANCHE(BE64(ping[i]));

    // CONSTANTE, DINAMICAMENTE ESCOLHIDO
    const u64* const restrict S = node->secret[(((((((A + B) ^ C) + D) ^ E) + F) ^ G) + H) % SECRET_PAIRS_N];

    // KEY[k] = (SECRET[s][k] + DYNAMIC[k])
    K[0] = S[0] + A;
    K[1] = S[1] + B;
    K[2] = S[2] + C;
    K[3] = S[3] + D;
    K[4] = S[4] + E;
    K[5] = S[5] + F;
    K[6] = S[6] + G;
    K[7] = S[7] + H;
}

// CONSTANT KEYS, FOR PING/PONG
// TODO: SO REFAZER ISSO SE TIVER MUDADO O SECRET (BY PASSWORD), O NODE ID OU O SELF ID
// TODO: COLD FUNCTION
static noinline void reset_node_ping_keys (node_s* const node, const uint self, const uint peer) {

    ASSERT(self < NODES_N);
    ASSERT(peer < NODES_N);
    ASSERT(self != peer);

    u64* restrict Kx;
    u64* restrict Ky;

    // CADA LADO USA UM PAR
    if (self > peer) {
        Kx = node->oKeys[O_PAIR_PING];
        Ky = node->iKeys[I_PAIR_PING];
    } else {
        Ky = node->oKeys[O_PAIR_PING];
        Kx = node->iKeys[I_PAIR_PING];
    }

    // TODO: OTHER CONSTANTS HERE
    u64 A = 0x05D171D85D80EBC4ULL, B = 0x9985E7AB107E8FCAULL, C = 0x263F3484D10AC084ULL, D = 0x47FDF736769A001AULL,
        E = 0xC6D8BC149729F1C4ULL, F = 0xC445BC1CB6B1BD4DULL, G = 0x96579857437F26A3ULL, H = 0x0780BABD0EF6CE16ULL;

    // MESMO QUE USE O MESMO PASSWORD ENTRE VARIOS NODES, NAO DEIXA QUE O PING KEYS SEJA O MESMO
    A += B += C += D += E += F += G += H +=
        0x0000000100000001ULL * (
            self > peer ? // MAS AMBOS OS LADOS TEM QUE GERAR O MESMO SECRET
                (self << 16) | peer :
                (peer << 16) | self
        )
    ;

    //
    for_count (p, SECRET_PAIRS_N)
        for_count (k, KEYS_N)
            __KEYS_AVALANCHE(node->secret[p][k]);

    Kx[0] = H; Kx[1] = G;
    Kx[2] = F; Kx[3] = E;
    Kx[4] = D; Kx[5] = C;
    Kx[6] = B; Kx[7] = A;

    //
    for_count (p, SECRET_PAIRS_N)
        for_count (k, KEYS_N)
            __KEYS_AVALANCHE(node->secret[p][k]);

    Ky[0] = A; Ky[1] = B;
    Ky[2] = C; Ky[3] = D;
    Ky[4] = E; Ky[5] = F;
    Ky[6] = G; Ky[7] = H;
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
