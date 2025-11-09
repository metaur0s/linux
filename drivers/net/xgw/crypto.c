
// !!!!!! TODO: XGW TO XGW REDIRECT WITHOUT GOING THROUGH IP STACK

static inline u64 bit_rotate_l64 (const u64 x, const uint q) { return (x << q) | (x >> (64 - q)); }
static inline u64 bit_rotate_r64 (const u64 x, const uint q) { return (x >> q) | (x << (64 - q)); }

static inline u64   swap64 (const u64 x) { return bit_rotate_l64(x, popcount64(x)); }
static inline u64 unswap64 (const u64 x) { return bit_rotate_r64(x, popcount64(x)); }

#define ENCX(x, s, m) (bit_rotate_l64((x), popcount64(m)) + (s))
#define DECX(x, s, m) (bit_rotate_r64((x) - s, popcount64(m)))

#define ENC(x) ENCX(ENCX(ENCX(ENCX((x), A, B), C, D), E, F), G, H)
#define DEC(x) DECX(DECX(DECX(DECX((x), G, H), E, F), C, D), A, B)

// TODO: CHOOSE THE RIGHT ONE HERE
#define _prefetch_secret __prefetch_r_temporal_low

static inline u64 encrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, u64 x) {

    ASSERT((end - pos) >= PKT_ALIGN_WORDS);
    ASSERT((end - pos) <= XGW_PAYLOAD_MAX/sizeof(u64));

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    do { //__prefetch_w_temporal_high(pos + 2);

        // READ THE ORIGINAL VALUE
        x = BE64(*pos);

        // WRITE THE ENCRYPTED VALUE
        *pos = BE64(ENC(x));

        // AVALANCHE OF ORIGINAL THROUGH KEYS
        A += C += x += E += G += x;
        B += D += x += F += H += x;

    } while (++pos != end);

    // RETURN THE HASH
    return x;
}

static inline u64 decrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, u64 x) {

    ASSERT((end - pos) >= PKT_ALIGN_WORDS);
    ASSERT((end - pos) <= XGW_PAYLOAD_MAX/sizeof(u64));

    // INITIAL KEYS, PER INTERVAL
    u64 A = K[0], B = K[1], C = K[2], D = K[3],
        E = K[4], F = K[5], G = K[6], H = K[7];

    do { //__prefetch_w_temporal_high(pos + 2);

        // READ THE ENCRYPTED VALUE AND DECRYPT IT
        x = DEC(BE64(*pos));

        // WRITE THE ORIGINAL VALUE
        *pos = BE64(x);

        // AVALANCHE OF ORIGINAL THROUGH KEYS
        A += C += x += E += G += x;
        B += D += x += F += H += x;

    } while (++pos != end);

    // RETURN THE HASH
    return x;
}

// USING SECRET S, APPLY RANDOM R, AND DERIVE KEY K
static void secret_derivate_random_as_key (const u64 S[SECRET_KEYS_N][K_LEN], const u64 R[K_LEN], u64 K[K_LEN]) {

    u64 x = 0;

    // LOAD DYNAMIC RANDOM AND ITS SUM
    for_count (k, K_LEN) {
        x += K[k] = BE64(R[k]);
    }   x += x >> 32;
        x += x >> 16;

    // CHOOSE AND APPLY SECRET
    const u64* const restrict s = S[x % SECRET_KEYS_N];

    // AS THE TRANSFORMER IS ALL THE RANDOMS ACCUMULATED,
    // THEN EACH WORD IS AFFECTED BY ALL THE OTHERS
    for_count (k, K_LEN)
        // THE TRANSFORMER AFFECTS THE SECRET
        // THE TRANSFORMER CONTINUES BEING AFFECTED BY
        //         RANDOM + (SECRET * TRANSFORMER)
        x += K[k] += s[k] * x;
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

    u64* restrict X; u64 sum;
    u64* restrict Y;

    // CADA LADO USA OS MESMOS PING/PONG, POREM INVERTIDOS
    //      SO OS PONTEIROS SAO INVERTIDOS
    //      AS SOMA SIMPLESMENTE É A MESMA (MAIOR | MENOR)
    if (self > peer) {
        sum = 0x0000000100000001ULL * ((self << 16) | peer);
        X = node->iKeys[I_KEY_PING];
        Y = node->oKeys[O_KEY_PING];
    } else {
        sum = 0x0000000100000001ULL * ((peer << 16) | self);
        X = node->oKeys[O_KEY_PING];
        Y = node->iKeys[I_KEY_PING];
    }

    // INITIALIZE THE KEYS
    // MESMO QUE USE O MESMO PASSWORD ENTRE VARIOS NODES, NAO DEIXA QUE O PING KEYS SEJA O MESMO
    for_count (k, 3 * K_LEN) X[k] = sum;
    for_count (k, 3 * K_LEN) Y[k] = sum;
    // TODO: SYN, PING, PONG

    // NOW MERGE WITH THE ENTIRE SECRET
    for_count (s, SECRET_KEYS_N) {
        for_count (k, K_LEN) {
            for_count (k2, 3 * K_LEN) sum += swap64(X[k2] += swap64(node->secret[s][k] + swap64(sum)));
            for_count (k2, 3 * K_LEN) sum += swap64(Y[k2] += swap64(node->secret[s][k] + swap64(sum)));
        }
    }

    // SET THE DEFAULT SYN CODES FOR THE PATHS
    // AN ATTACKER ABLE TO WATCH ONE OF THEM CAN'T KNOW THE OTHER ONES
    for_count (pid, PATHS_N) {
        node->syns[pid] = sum + popcount(sum) * sum;
        sum += swap64(sum);
    }
}

// REPETE ELE ATE PREENCHER TODA A ARRAY
static void copy_and_fill (void* const restrict dst, const uint dstSize, const void* const restrict src, uint srcSize) {

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
    u64 A = S[0][0], B = S[0][1], C = S[0][2], D = S[0][3];

    // NAO DEIXA SER APENAS UMA REPETICAO
    for_count (s, SECRET_KEYS_N)
        for_count (k, K_LEN)
            A += B += C += D +=
                S[s][k] =
                    swap64(swap64(swap64(S[s][k] + D) + C) + B) + A;

    // SHUFFLE
    for_count (c, PASSWORD_ROUNDS) {
        for_count (s, SECRET_KEYS_N) {
            for_count (k, K_LEN) {

                A += S[D % SECRET_KEYS_N][C % K_LEN] * B;
                B += S[C % SECRET_KEYS_N][A % K_LEN] * D;
                C += S[B % SECRET_KEYS_N][D % K_LEN] * A;
                D += S[A % SECRET_KEYS_N][B % K_LEN] * C;

                A += B += C += D +=
                    S[s][k] =
                        swap64(swap64(swap64(S[s][k] + D) + C) + B) + A;
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
#define _PKT_SEED(pkt) BE64(pkt->x.info ^ pkt->x.time)

// A IDÉIA É ASSUMIR QUE O SIZE É SEMPRE MULTIPLO DE 64-BITS.
// DAÍ O RESTO QUE PASSAR DISSO, É "EXPULSO" DO ALIGN, FAZENDO ELE COMECAR MAIS PARA FRENTE.
#define _PKT_START(pkt, size) (PTR(pkt->p) + (size % sizeof(pkt->p[0])))
#define _PKT_END(pkt, size)   (PTR(pkt->p) + PKT_ALIGN_SIZE + size)

// NOTE: TEM QUE FAZER APOS TER SETADO O PKT INFO E RCOUNTER
#define pkt_encrypt(node, o, pkt, size) encrypt(node->oKeys[o], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt))
#define pkt_decrypt(node, i, pkt, size) decrypt(node->iKeys[i], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt))
