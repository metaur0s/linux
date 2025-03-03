
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
static inline u64 _PKT_SEED (const u64 a, const u64 b) {

    return ((a + b) * a) + b;
}

// TODO: O SCOUNTER IDENTIFICA O MEU I SENDO ENSINADO
// TODO: O DCOUNTER IDENTIFICA O MEU O SENDO USADO

//
#define _PKT_START PTR(pkt) + PKT_SIZE + size % sizeof(u64)
#define _PKT_END   PTR(pkt) + PKT_SIZE + PKT_ALIGN_SIZE + size

// NOTE: TEM QUE FAZER APOS TER SETADO O PKT INFO E SCOUNTER
#define pkt_encrypt(node, o, pkt, size, dcounter) ((dcounter) ^ encrypt(node->oKeys[o], _PKT_START, _PKT_END, _PKT_SEED(BE64(pkt->x.info), BE64(pkt->x.scounter))))
#define pkt_decrypt(node, i, pkt, size, hash)     ((hash)     ^ decrypt(node->iKeys[i], _PKT_START, _PKT_END, _PKT_SEED(BE64(pkt->x.info), BE64(pkt->x.scounter))))

// NAO FAZ UM SWAP FINAL POIS O VALOR É EXPOSTO K[4] ISSO SERIA INUTIL
#define ENC(x) (  swap64(  swap64(  swap64(  swap64(  swap64(  swap64(  swap64((x) + A) + B) + C) + D) + E) + F) + G) + H)
#define DEC(x) (unswap64(unswap64(unswap64(unswap64(unswap64(unswap64(unswap64((x) - H) - G) - F) - E) - D) - C) - B) - A)

static inline u64 encrypt (const u64 K[K_LEN], u64* restrict ptr, u64* restrict const lmt, u64 x) {

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    loop {

        // AVALANCHE OF X THROUGH KEYS
        D += C += B += A += x;
        H += G += F += E += x;

        A += K[C % K_LEN] * H;
        B += K[E % K_LEN] * G;
        C += K[D % K_LEN] * F;
        D += K[A % K_LEN] * E;
        E += K[H % K_LEN] * D;
        F += K[G % K_LEN] * C;
        G += K[F % K_LEN] * B;
        H += K[B % K_LEN] * A;

        if (ptr == lmt)
            // RETURN THE HASH
            return ((((((A + B) ^ C) + D) ^ E) + F) ^ G) + H;

        // READ THE ORIGINAL VALUE
        x = BE64(*ptr);

        // WRITE THE ENCRYPTED VALUE
        *ptr++ = BE64(ENC(x));
    }
}

static inline u64 decrypt (const u64 K[K_LEN], u64* restrict ptr, u64* restrict const lmt, u64 x) {

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    loop {

        // AVALANCHE OF X THROUGH KEYS
        D += C += B += A += x;
        H += G += F += E += x;

        A += K[C % K_LEN] * H;
        B += K[E % K_LEN] * G;
        C += K[D % K_LEN] * F;
        D += K[A % K_LEN] * E;
        E += K[H % K_LEN] * D;
        F += K[G % K_LEN] * C;
        G += K[F % K_LEN] * B;
        H += K[B % K_LEN] * A;

        if (ptr == lmt)
            // RETURN THE HASH
            return ((((((A + B) ^ C) + D) ^ E) + F) ^ G) + H;

        // DECRYPT THE VALUE
        x = DEC(BE64(*ptr));

        // WRITE THE ORIGINAL VALUE
        *ptr++ = BE64(x);
    }
}

// MUST NOT EXPOSE SECRETS
static noinline void learn (const u64 secret[SECRET_KEYS_N][K_LEN], const u64 R[K_LEN], u64 K[K_LEN]) {

    // TRANSFORMER
    u64 t = 0;

    // LOAD DINAMICO ALEATORIO
    for_count (k, K_LEN) {
        t += K[k] = BE64(R[k]);
    }   t += t >> 32;
        t += t >> 16;

    // MERGE WITH CONSTANTE, DINAMICAMENTE ESCOLHIDO
    const u64* const restrict S = secret[t % SECRET_KEYS_N];

    for_count (k, K_LEN)
        t = K[k] = swap64(swap64(K[k] + S[k]) + t);
}

// CONSTANT KEYS, FOR PING/PONG
// TODO: SO REFAZER ISSO SE TIVER MUDADO O SECRET (BY PASSWORD), O NODE ID OU O SELF ID
// TODO: COLD FUNCTION
// MUST PROVE THE PING WILL GENERATE THE SAME KEYS
static noinline void reset_node_ping_keys (node_s* const node, const uint self, const uint peer) {

    ASSERT(self < NODES_N);
    ASSERT(peer < NODES_N);
    ASSERT(self != peer);

    u64* restrict Kx; u64 x;
    u64* restrict Ky; u64 y;

    // CADA LADO USA UM PAR
    if (self > peer) {
        Kx = node->oKeys[O_KEY_PING];
        Ky = node->iKeys[I_KEY_PING];
    } else {
        Kx = node->iKeys[I_KEY_PING];
        Ky = node->oKeys[O_KEY_PING];
    }

    // MESMO QUE USE O MESMO PASSWORD ENTRE VARIOS NODES, NAO DEIXA QUE O PING KEYS SEJA O MESMO
    if (self > peer) {
        x = self;
        y = peer;
    } else {
        x = peer;
        y = self;
    }

    for_count (k, K_LEN) Kx[k] = x;
    for_count (k, K_LEN) Ky[k] = y;

    for_count (s, SECRET_KEYS_N) {

        for_count (k, K_LEN) {
            x += Kx[k] += x ^ node->secret[s][k];
            x += Kx[k] += x * node->secret[s][x % K_LEN];
        }

        for_count (k, K_LEN) {
            y += Ky[k] += y ^ node->secret[s][k];
            y += Ky[k] += y * node->secret[s][y % K_LEN];
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
    for_count (p, SECRET_KEYS_N)
        for_count (k, K_LEN)
            node->secret[p][k]
     = BE64(node->secret[p][k]);
#endif

    // NAO DEIXA SER APENAS UMA REPETICAO
    for_count (p, SECRET_KEYS_N)
        for_count (k, K_LEN)
            node->secret[p][k] +=
           (node->secret[p][k] * p) ^
           (node->secret[p][k] * k);

    // INITIAL KEYS, PER INTERVAL
    u64 A = node->secret[0][0], B = node->secret[0][1], C = node->secret[0][2], D = node->secret[0][3],
        E = node->secret[0][4], F = node->secret[0][5], G = node->secret[0][6], H = node->secret[0][7];

    for_count (c, PASSWORD_ROUNDS) {
        for_count (s, SECRET_KEYS_N) {
            for_count (k, K_LEN) {

                A += node->secret[H % SECRET_KEYS_N][C % K_LEN] * E;
                B += node->secret[G % SECRET_KEYS_N][D % K_LEN] * F;
                C += node->secret[F % SECRET_KEYS_N][E % K_LEN] * G;
                D += node->secret[E % SECRET_KEYS_N][F % K_LEN] * H;
                E += node->secret[D % SECRET_KEYS_N][G % K_LEN] * A;
                F += node->secret[C % SECRET_KEYS_N][H % K_LEN] * B;
                G += node->secret[B % SECRET_KEYS_N][A % K_LEN] * C;
                H += node->secret[A % SECRET_KEYS_N][B % K_LEN] * D;

                node->secret[s][k] = ENC(node->secret[s][k]);
            }
        }
    }
}
