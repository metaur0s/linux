
// NAO É RANDOM NO SENTIDO DE NAO ADIVINHAVEL, MAS FICA NAO TAO SEQUENCIAL E ALTERANDO DIFERENTES BITS
static u64 random64 (const u64 seed) {

#ifdef CONFIG_XGW_RDRAND
    u64 R; __builtin_ia32_rdrand64_step(&R);
#else // TODO:
    u64 R = 0;
#endif

    return atomic_add(&_xrnd, swap64(swap64(_xrnd + seed) + __builtin_ia32_rdtsc()) + R);
}
