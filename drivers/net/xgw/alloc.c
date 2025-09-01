
static inline uint paged_order (const size_t size) {

    uint real = PAGE_SIZE;

    while (real < size)
           real <<= 1;

    return __ctz(real / PAGE_SIZE);
}

static void paged_free (void* const a, const size_t size) {

    free_pages((uintptr_t)a, paged_order(size));
}

static void* paged_alloc (const size_t size) {

    return (void*)__get_free_pages(GFP_NOWAIT, paged_order(size));
}
