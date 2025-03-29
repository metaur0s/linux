
static inline void ping_receive (node_s* const node, const ping_s* const ping) {

    u64 K[K_LEN];

    // LEARN HIS INPUT KEYS (MY OUTPUT KEYS)
    const uint ver = BE8(ping->ver);

    ASSERT(ver < I_KEYS_DYNAMIC);

    secret_derivate_random_as_key(node->secret, ping->rnd, K);

    // FAZ ISSO PRIMEIRO ANTES DE LIBERAR O PATH PARA ENVIAR
    const uint o = __atomic_add_fetch(&node->oCycle, 1, __ATOMIC_ACQUIRE) % O_KEYS_DYNAMIC;
                                       node->oVersions[o] = ver;
                                memcpy(node->oKeys[o], K, sizeof(K));
                     __atomic_store_n(&node->oIndex, o,  __ATOMIC_RELEASE);
}

static void ping_send (node_s* const node, path_s* const path, const pkt_s* const skel, const u64 now, const u64 rtime, const uint o) {

    uint stat;

    skb_s* const skb = alloc_skb(64 + PKT_SIZE + PKT_ALIGN_SIZE + PING_SIZE + 64, GFP_ATOMIC);

    if (skb) {

        // TODO: USA O SKB_DATA ALIGNED
        ping_s* const ping = SKB_DATA(skb) + 64 + PKT_SIZE + PKT_ALIGN_SIZE;

        // GERA AS KEYS
        random64_n(PTR(ping), PING_RANDOMS_N, SUFFIX_ULL(CONFIG_XGW_RANDOM_PING));

        ping->time = BE64(now);

        if (o != O_KEY_SYN) {

            // A CADA PING/PONG O SLOT MAIS ANTIGO É RECICLADO.
            // ENTÃO AS KEYS MAIS ANTIGAS SÃO AUTOMATICAMENTE DESCARTADAS.
            // OVERFLOWS SERAO PROBLEMAS, ENTAO TEM QUE USAR PALAVRA GRANDE.
            const uint i = __atomic_add_fetch(&node->iCycle, 1, __ATOMIC_RELAXED) % I_KEYS_DYNAMIC;

            ping->ver = BE8(i); // OVERWRITE WITH THE VERSION

            // SEM ATOMICITY/BARRIER POIS ESTA USANDO UMA KEY JA EXPIRADA
            secret_derivate_random_as_key(node->secret, ping->rnd, node->iKeys[i]);
        }

        pkt_encapsulate(node, o, rtime, skel, skb, ping, PING_SIZE);

        skb->ip_summed = CHECKSUM_NONE;

        if (dev_queue_xmit(skb))
            // FAILED TO SEND THE SKB
            // NOTE: THE SKB WAS ALREADY CONSUMED
            stat = PSTATS_O_PING_SEND_FAILED;
        else
            stat = PSTATS_O_PING_OK;
    } else // FAILED TO ALLOCATE SKB
        stat = PSTATS_O_PING_SKB_FAILED;

    // NOTE: WE WILL INFORM THE TOTAL SIZE SENT THROUGHT THE PHYSICAL INTERFACE
    stat_inc_bytes(&path->stats[stat].bytes, skel->hsize + PKT_ALIGN_SIZE + PING_SIZE);
    stat_inc_count(&path->stats[stat].count);
}
