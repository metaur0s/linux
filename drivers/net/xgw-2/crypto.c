
// !!!!!! TODO: XGW TO XGW REDIRECT WITHOUT GOING THROUGH IP STACK

// AUTHENTICITY AND INTEGRITY
// - SRC HOST ID
// - DST HOST ID
// - PATH ID
// - RECEIVER IN SLOT
// - DATA SIZE
// AUTHENTICITY, INTEGRITY AND PRIVACY
// - DATA

/* NOTE: QUALQUER ALTERAÇÃO EM UM BIT DO INFO OU DO SCOUNTER TEM QUE RESULTAR EM ALGO DIFERENTE AQUI

def compute (a, b):
    #return ((a + b) ^ a) + b
    #return (((a + b) ^ (a * b)) + a) ^ b
    return ((a + b) * a) + b

for a in (0xAABBCC0000, 0xAABBCC0001, 0xAABBCCDD00, 0xAABBCCDDEE, 0xAABBCCDDFF):
    for b in (0xAABBCC0000, 0xAABBCC0001, 0xAABBCCDD00, 0xAABBCCDDEE, 0xAABBCCDDFF):
        cksum = compute(a, b)
        assert cksum != compute(a + 1, b)
        assert cksum != compute(a - 1, b)
        assert cksum != compute(a ^ 1, b)
        assert cksum != compute(a    , b + 1)
        assert cksum != compute(a    , b - 1)
        assert cksum != compute(a    , b ^ 1)
        assert cksum != compute(a + 1, b + 1)
        assert cksum != compute(a - 1, b - 1)
        assert cksum != compute(a ^ 1, b ^ 1)
        assert cksum != compute(a + 1, b - 1)
        assert cksum != compute(a + 1, b ^ 1)
        assert cksum != compute(a - 1, b + 1)
        assert cksum != compute(a - 1, b ^ 1)
        assert cksum != compute(a ^ 1, b + 1)
        assert cksum != compute(a ^ 1, b - 1)
*/
static inline u64 _PKT_SEED (const pkt_s* const pkt) {

    const u64 a = BE64(pkt->x.info);
    const u64 b = BE64(pkt->x.scounter);

    return ((a + b) * a) + b;
}

// A IDÉIA É ASSUMIR QUE O SIZE É SEMPRE MULTIPLO DE 64-BITS.
// DAÍ O RESTO QUE PASSAR DISSO, É "EXPULSO" DO ALIGN, FAZENDO ELE COMECAR MAIS PARA FRENTE.
static inline u64* _PKT_START (const pkt_s* const pkt, const uint size)
    { return PTR(pkt) + PKT_SIZE + (size % sizeof(pkt->p[0])); }

static inline u64* _PKT_END (const pkt_s* const pkt, const uint size)
    { return PTR(pkt) + PKT_SIZE + PKT_ALIGN_SIZE + size; }

// NOTE: TEM QUE FAZER APOS TER SETADO O PKT INFO E SCOUNTER
#define pkt_encrypt(node, o, pkt, size, dcounter) ((dcounter) ^ encrypt(node->oKeys[o], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt)))
#define pkt_decrypt(node, i, pkt, size, hash)     ((hash)     ^ decrypt(node->iKeys[i], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt)))

// NAO FAZ UM SWAP FINAL POIS O VALOR É EXPOSTO K[4] ISSO SERIA INUTIL
#define ENC(x) (  swap64(  swap64(  swap64(  swap64(  swap64(  swap64(  swap64((x) + A) + B) + C) + D) + E) + F) + G) + H)
#define DEC(x) (unswap64(unswap64(unswap64(unswap64(unswap64(unswap64(unswap64((x) - H) - G) - F) - E) - D) - C) - B) - A)

static inline u64 encrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, u64 x) {

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    loop {

        // AVALANCHE OF X THROUGH KEYS
        H += G += F += E += D += C += B += A += x;

        A += K[C % K_LEN] * H;
        B += K[E % K_LEN] * G;
        C += K[D % K_LEN] * F;
        D += K[A % K_LEN] * E;
        E += K[H % K_LEN] * D;
        F += K[G % K_LEN] * C;
        G += K[F % K_LEN] * B;
        H += K[B % K_LEN] * A;

        if (pos == end)
            // RETURN THE HASH
            return A + B + C + D + E + F + G + H;

        // READ THE ORIGINAL VALUE
        x = BE64(*pos);

        // WRITE THE ENCRYPTED VALUE
        *pos++ = BE64(ENC(x));
    }
}

static inline u64 decrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, u64 x) {

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    loop {

        // AVALANCHE OF X THROUGH KEYS
        H += G += F += E += D += C += B += A += x;

        A += K[C % K_LEN] * H;
        B += K[E % K_LEN] * G;
        C += K[D % K_LEN] * F;
        D += K[A % K_LEN] * E;
        E += K[H % K_LEN] * D;
        F += K[G % K_LEN] * C;
        G += K[F % K_LEN] * B;
        H += K[B % K_LEN] * A;

        if (pos == end)
            // RETURN THE HASH
            return A + B + C + D + E + F + G + H;

        // READ THE ENCRYPTED VALUE AND DECRYPT IT
        x = DEC(BE64(*pos));

        // WRITE THE ORIGINAL VALUE
        *pos++ = BE64(x);
    }
}

// USING SECRET S, APPLY RANDOM R, AND DERIVE KEY K
static void secret_derivate_random_as_key (const u64 S[SECRET_KEYS_N][K_LEN], const u64 R[K_LEN], u64 K[K_LEN]) {

    // TRANSFORMER
    u64 A = 0xAE2A134212DD6AEEULL, B = 0x2CD7FAE5AB5C2DF0ULL, C = 0x30015620CA42573EULL, D = 0x24F5318E88AF90ADULL,
        E = 0x42105E379B508E9DULL, F = 0x45B173FCA98E53FBULL, G = 0x6F725D1874FB2ECBULL, H = 0x36A485858CB60FC9ULL;

    // LOAD DYNAMIC RANDOM
    for_count (k, K_LEN)
        A += B += C += D += E += F += G += H += K[k] =
            swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(BE64(R[k]) + H) + G) + F) + E) + D) + C) + B) + A);

    // DYNAMICALY CHOOSE CONSTANT SECRET
    const u64* const restrict s = S[(((((((A + B) ^ C) + D) ^ E) + F) ^ G) + H) % SECRET_KEYS_N];

    // MERGE
    for_count (k, K_LEN)
        A += B += C += D += E += F += G += H += K[k] =
            swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(K[k] + S[k]) + H) + G) + F) + E) + D) + C) + B) + A);
}

// CONSTANT KEYS, FOR PING/PONG
// TODO: SO REFAZER ISSO SE TIVER MUDADO O SECRET (BY PASSWORD), O NODE ID OU O SELF ID
// TODO: COLD FUNCTION
// MUST PROVE THE PING WILL GENERATE THE SAME KEYS
// --
// WILL GENERATE TWO KEYS.
// A NODE WILL USE THEM FOR IN/OUT
// IT'S PEER WILL USE THEM FOR OUT/IN
// --
static void reset_node_ping_keys (node_s* const node, const uint self, const uint peer) {

    ASSERT(self < NODES_N);
    ASSERT(peer < NODES_N);
    ASSERT(self != peer);

    u64* restrict AK; u64 a = 0x0001000100010001ULL * self;
    u64* restrict BK; u64 b = 0x0001000100010001ULL * peer;

    if (a > b) {
        a ^= (b ^= (a ^= b)); // SWAP THEM, SO WE ALWAYS HAVE THE SAME A AND B
        // CADA LADO USA OS MESMOS PING/PONG, POREM INVERTIDOS
        AK = node->oKeys[O_KEY_PING];
        BK = node->iKeys[I_KEY_PING];
    } else {
        AK = node->iKeys[I_KEY_PING];
        BK = node->oKeys[O_KEY_PING];
    }

    // INITIALIZE THE KEYS
    // MESMO QUE USE O MESMO PASSWORD ENTRE VARIOS NODES, NAO DEIXA QUE O PING KEYS SEJA O MESMO
    for_count (k, K_LEN) AK[k] = a += 0xA601E857DF7F6A12ULL;
    for_count (k, K_LEN) BK[k] = b += 0xF0778A61A03B4480ULL;

    // NOW MERGE WITH THE ENTIRE SECRET
    u64 A = 0xAFEE0C56092DF220ULL, B = 0x8BD98EC995251C3CULL, C = 0x9A3943E82D8DD4D2ULL, D = 0x501FBD1644159395ULL,
        E = 0x02E12A80B229ADF5ULL, F = 0x52DC3014C0C6A1BAULL, G = 0x89DEA1B4941E360CULL, H = 0xC1B7B1DD4CA86D42ULL;

    for_count (s, SECRET_KEYS_N) {
        for_count (k, K_LEN) A += B += C += D += E += F += G += H += AK[k] = swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(AK[k] + node->secret[s][k]) + H) + G) + F) + E) + D) + C) + B) + A);
        for_count (k, K_LEN) A += B += C += D += E += F += G += H += BK[k] = swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(BK[k] + node->secret[s][k]) + H) + G) + F) + E) + D) + C) + B) + A);
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
    u64 A = 0x47092E83C59147FBULL, B = 0x6B80F1DD47505E84ULL, C = 0x8ACB8D82EBE013B0ULL, D = 0xEF7D87567DABC6DDULL,
        E = 0x879E9AF60BA2284DULL, F = 0x16CC54BBE05DA85FULL, G = 0x76A45CC8348064B5ULL, H = 0x03781F048D90B044ULL;

    // NAO DEIXA SER APENAS UMA REPETICAO
    for_count (s, SECRET_KEYS_N)
        for_count (k, K_LEN)
            A += B += C += D += E += F += G += H += S[s][k] =
                swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(S[s][k] + H) + G) + F) + E) + D) + C) + B) + A);

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

                S[s][k] = swap64(swap64(swap64(swap64(swap64(swap64(swap64(swap64(S[s][k] + H) + G) + F) + E) + D) + C) + B) + A);
            }
        }
    }
}
