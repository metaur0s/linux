
// X86 RDRAND
#ifdef CONFIG_XGW_RDRAND
static inline u64 rdrand64 (void) {

    u64 r;

    __builtin_ia32_rdrand64_step(&r);

    return r;
}
#endif

// NAO É RANDOM NO SENTIDO DE NAO ADIVINHAVEL, MAS FICA NAO TAO SEQUENCIAL E ALTERANDO DIFERENTES BITS
static void random64_n (u64 words[], uint n, u64 seed) {

#ifdef CONFIG_XGW_RDRAND
    seed += rdrand64();
#endif
#ifdef CONFIG_XGW_RDTSC
    seed += __builtin_ia32_rdtsc();
#endif

    for_count (i, n) {
        seed += _xrnd[seed % RANDOM_LEN];
        seed += _xrnd[seed % RANDOM_LEN] * seed;
                _xrnd[seed % RANDOM_LEN] = seed;
        words[i] = seed;
    }
}

static u64 random64 (u64 seed) {

#ifdef CONFIG_XGW_RDRAND
    seed += rdrand64();
#endif
#ifdef CONFIG_XGW_RDTSC
    seed += __builtin_ia32_rdtsc();
#endif

    seed += _xrnd[seed % RANDOM_LEN];
    seed += _xrnd[seed % RANDOM_LEN] * seed;
            _xrnd[seed % RANDOM_LEN] = seed;

    return seed;
}

static void random64_init (void) {

    u64 seed = SUFFIX_ULL(CONFIG_XGW_RANDOM_PING);

#ifdef CONFIG_XGW_RDTSC
    seed += __builtin_ia32_rdtsc();
#endif

    for_count (i, RANDOM_LEN) {
        seed += seed * popcount(seed);
#ifdef CONFIG_XGW_RDRAND
        seed += rdrand64();
#endif
        _xrnd[i] = seed;
    }
}
