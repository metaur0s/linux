
static inline u64 __u64x8_sum_reduced (const u64x8 V[], const uint n) {

    u64x8 v = { 0, 0, 0, 0, 0, 0, 0, 0 };

    for (uint i = 0; i != n; i++)
        v += V[i];

    return v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7];
}
