#define PPP_PROTO_IP4 0x0021
#define PPP_PROTO_IP6 0x0057

BUILD_ASSERT(IPPROTO_UDP != PPP_PROTO_IP4);
BUILD_ASSERT(IPPROTO_UDP != PPP_PROTO_IP6);
BUILD_ASSERT(IPPROTO_UDP != ETH_P_IP);
BUILD_ASSERT(IPPROTO_UDP != ETH_P_IPV6);

BUILD_ASSERT(IPPROTO_TCP != PPP_PROTO_IP4);
BUILD_ASSERT(IPPROTO_TCP != PPP_PROTO_IP6);
BUILD_ASSERT(IPPROTO_TCP != ETH_P_IP);
BUILD_ASSERT(IPPROTO_TCP != ETH_P_IPV6);

static noinline void __optimize_size in_discover (const path_s* const path, const skb_s* const skb, pkt_s* const skel) {

    ASSERT(path->info & S_SERVER);

    const void* orig = SKB_NETWORK(skb);

    // POR SEGURANCA VAMOS EXIGIR ETH_HLEN
    // É MELHOR FICAR SEM HARDWARE HEADER DO QUE PROBLEMAS MAIORES
    uint T = skb->mac_len == ETH_HLEN ? __ETH : 0;

    uint proto = skb->protocol;

    switch (proto) {
        case BE16(ETH_P_8021Q):
        case BE16(ETH_P_8021AD): // NOTE: PODE ACABAR VIRANDO __VLAN SEM __ETH
            T |= __VLAN;
            proto = ((hdr_vlan_s*)orig)->proto;
            orig += sizeof(hdr_vlan_s);
            break;
    }

    switch (proto) {
        case BE16(ETH_P_PPP_SES):
            T |= __PPP;
            proto = ((hdr_ppp_s*)orig)->proto;
            orig += sizeof(hdr_ppp_s);
            break;
    }
    
    switch (proto) {
        case BE16(PPP_PROTO_IP4):
        case BE16(ETH_P_IP):
            T |= __IP4;
            proto = ((hdr_ip4_s*)orig)->proto;
            orig += sizeof(hdr_ip4_s);
            break;
        case BE16(PPP_PROTO_IP6):
        case BE16(ETH_P_IPV6):
            T |= __IP6;
            proto = ((hdr_ip6_s*)orig)->proto;
            orig += sizeof(hdr_ip6_s);
            break;
    }

    switch (proto) {
        case BE8(IPPROTO_UDP):
            T |= __UDP;
            orig += sizeof(hdr_udp_s);
            break;
        case BE8(IPPROTO_TCP):
            T |= __TCP;
            orig += sizeof(hdr_tcp_s);
            break;
    }

    //
    orig -= offsetof(pkt_s, x);

    memcpy(skel, &models[T], sizeof(pkt_s));

    ASSERT(skel->type == T);

    if (T & __ETH) {
        memcpy(PTR(skel) + skel->moffset + 6, orig + skel->moffset + 0, 6);
        memcpy(PTR(skel) + skel->moffset + 0, orig + skel->moffset + 6, 6);
    }

    if (T & __VLAN) // COPIA O VPROTO E O VID
        memcpy(PTR(skel) + skel->moffset + 12, orig + skel->moffset + 12, 4);

    if (T & __PPP)
        // COPIA O CODE, SESSION, SIZE E PROTOCOL
        // O SIZE OVERWRITED DEPOIS
        memcpy(PTR(skel) + skel->_reserved, orig + skel->_reserved, 8);

    if (T & __IP4) {
        memcpy(PTR(skel) + skel->Noffset + 16, orig + skel->Noffset + 12, 4);
        memcpy(PTR(skel) + skel->Noffset + 12, orig + skel->Noffset + 16, 4);
    } elif (T & __IP6) {
        memcpy(PTR(skel) + skel->Noffset + 24, orig + skel->Noffset +  8, 16);
        memcpy(PTR(skel) + skel->Noffset +  8, orig + skel->Noffset + 24, 16);
    }

    if (T & (__UDP | __TCP)) {
        memcpy(PTR(skel) + skel->toffset + 0, orig + skel->toffset + 2, 2);
        memcpy(PTR(skel) + skel->toffset + 2, orig + skel->toffset + 0, 2);
    }

    // TEM QUE FAZER ISSO AQUI
    skel->x.dst  = ((pkt_s*)orig)->x.src;
    skel->x.src  = ((pkt_s*)orig)->x.dst;
    skel->x.path = ((pkt_s*)orig)->x.path;
 // skel->x.version --> ON encrypt()
 // skel->x.dsize   --> ON encrypt()
 // skel->x.seed    --> ON encrypt()
 // skel->x.hash    --> ON encrypt()

    // PRECISA DISSO POIS SE FOR VLAN AI DIFERE
    skel->protocol = skb->protocol;
    skel->phys     = skb->dev;

    // SET TOS/TTL FROM PATH
    if (T & __IP4) { hdr_ip4_s* const ip4 = PKT_IP4(skel);
        ip4->tos = BE8(path->tos);
        ip4->ttl = BE8(path->ttl);
    } elif (T & __IP6) { hdr_ip6_s* const ip6 = PKT_IP6(skel);
        ip6->tos = BE8(path->tos);
        ip6->ttl = BE8(path->ttl);
        ip6->flow = BE16(0x1111U * path->pid);
    }
}

// PATH->RCOUNTER
#define COUNTER_LISTENING       0 // LISTENING  (UNLOCKED)
#define COUNTER_ACCEPTING       1 // LISTENING  (LOCKED)
#define COUNTER_CONNECTING  65537 // CONNECTING

// PING DESTINATION'S COUNTER
#define COUNTER_SYN 0

static inline int __compare_exchange64_cst (volatile u64* const where, u64 old, const u64 new) {

    return __atomic_compare_exchange_n(where, &old, new, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

static noinline int __optimize_size in_pp (node_s* const node, skb_s* const iskb, const pkt_s* const pkt, const uint size, const u64 p_lcounter) {

    path_s* const path = &node->paths[BE8(pkt->x.path)];

    if (size == PONG_SIZE) {

        const u64 p_rcounter = BE64(pkt->p[1 + P__CTR]);

        if (p_rcounter <= COUNTER_CONNECTING)
            // HIS COUNTER IS INVALID
            return PSTATS_I_PONG_RCOUNTER_INVALID;

        // PONGS TEM QUE SER DENTRO DO INTERVALO
        if (!__compare_exchange64_cst(&path->lcounter, p_lcounter, get_jiffies_64()))
            // O RACE PODE TER ACONTECIDO JUNTO COM OUTRO RECEIVE, OU O KEEPER ACABA DE AVANCAR
            return PSTATS_I_PONG_LCOUNTER_MISMATCH;

        // SAVED O HORARIO EM QUE RECEBEU O PONG PARA O LCOUNTER ATUAL

        // PATH->RCOUNTER IS RESPONSIBILITY OF THE PING, NOT THE PONG;
        // BUT IF THIS PONG IS THE SYN-ACK, THIS IS WHERE THE CLIENT DISCOVERS THE SERVER COUNTER,
        // AND THEN STOPS SENDING SYN
        __compare_exchange64_cst(&path->rcounter, COUNTER_CONNECTING, p_rcounter);

        // SAVE REMOTE COUNTER
        // NOTE: HERE WE RACE WITH ABOVE; THE KEEPEER MAY HAVE READ AN INVALID node->rcounter
        // BUT THAT WOULD MEAN WE RECEIED A PONG AFTER A KEEPER INTERVAL
        __atomic_store_n(&node->rcounter, p_rcounter, __ATOMIC_RELAXED);

        return PSTATS_I_PONG_GOOD;
    }

    if (size == PING_SIZE) {

        pkt_s* skel; pkt_s skel_;

        const u64 p_rcounter = BE64(pkt->p[1 + P__CTR]);

        if (p_rcounter <= COUNTER_CONNECTING)
            // HIS COUNTER IS INVALID
            // CANNOT BECAME LISTENING/DISCOVERING/CONNECTING
            return PSTATS_I_PING_RCOUNTER_INVALID;

        if (p_lcounter != COUNTER_SYN) { // NOTE: THE SIGN HE SENT IS FROM THE NODE->LCOUNTER; IT WOULD BE CORRECT EVEN WITHOUT HANDSHAKE, BUT KEEPER WON'T SEND WITHOUT ONE

            u64 node_lcounter = __atomic_load_n(&node->lcounter, __ATOMIC_RELAXED);
            u64 path_rcounter = __atomic_load_n(&path->rcounter, __ATOMIC_RELAXED); // COUNTER DELE, DO ULTIMO PING QUE ELE NOS MANDOU

            // NOT A SYN; HE MUST KNOW OUR COUNTER
            // NOTE: CONSIDERAR CLOCK SKELS E INTERVALOS ENTRE PINGS
            if (ABS_DIFF(node_lcounter, p_lcounter) > 2)
                // HE DOESNT KNOW MY COUNTER
                return PSTATS_I_PING_LCOUNTER_MISMATCH;

            if (path_rcounter == COUNTER_CONNECTING)
                // SOMOS UM CLIENTE SE CONECTANDO, E ELE NOS ENVIOU UM PING
                return PSTATS_I_PING_WHILE_CONNECTING;

            if (path_rcounter >= COUNTER_CONNECTING) {
                // THE PATH IS SYNCED WITH HIS COUNTER

                if (p_rcounter == path_rcounter)
                    // REPEATED (LAST)
                    return PSTATS_I_PING_RCOUNTER_REPEATED;

                if (p_rcounter < path_rcounter)
                    // REPEATED (OLD)
                    return PSTATS_I_PING_RCOUNTER_OLD;

                if (p_rcounter > (path_rcounter + 65536))
                    // PARA QUE TENHAMOS PERDIDO TANTOS PINGS DELE, ERA PARA TERMOS RESETADO...
                    return PSTATS_I_PING_RCOUNTER_BAD;

                if (p_rcounter != (path_rcounter + 1))
                    // ALGUNS FORAM PERDIDOS
                    __atomic_add_fetch(&path->pstats[PSTATS_I_PING_MISSED].count, p_rcounter - (path_rcounter + 1), __ATOMIC_RELAXED);

                // SAVE HIS SEQ
                if (!__atomic_compare_exchange_n(&path->rcounter, &path_rcounter, p_rcounter, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
                    // ANOTHER ACK HAPPENED SIMULTANEOUSLY, AND THIS ONE WILL BE DISCARDED
                    return PSTATS_I_PING_RACED;

            } else {
                // path->rcounter ==
                //      a) COUNTER_LISTENING (DESDE O KEEPER - START)
                //      b) COUNTER_ACCEPTING (AQUI MESMO, RACED)
                u64 path_rcounter_listening = COUNTER_LISTENING;

                if (__atomic_compare_exchange_n(&path->rcounter, &path_rcounter_listening, COUNTER_ACCEPTING, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
      // a)            WE ARE THE SERVER, AND THIS IS THE FIRST PING THE CLIENT SENT WITH OUR COUNTER
                    // DISCOVER THE CLIENT PATH
                        in_discover(path, iskb, &path->skel);
                    // DISCOVER THE CLIENT COUNTER
                        __atomic_store_n(&node->rcounter, p_rcounter, __ATOMIC_RELAXED);
                    // START SENDING PINGS
                        __atomic_store_n(&path->rcounter, p_rcounter, __ATOMIC_RELEASE);
                } else
      // b)            RACED COM OUTRO ACCEPT
                    return PSTATS_I_PING_RACED;
            }

            u64 keys [KEYS_N];

            learn(node, pkt->p + 1, keys);

            // FAZ ISSO PRIMEIRO ANTES DE LIBERAR O PATH PARA ENVIAR
            // NOTE: A CADA INTERVALO SAO ENVIADOS PINGS POR TODOS OS PATHS,
            //       ENTAO PODE ACABAR TENDO RACE CONDITION AQUI.
            // POR PRECAUCAO O IDEAL É TER MAIS ENTRADAS NA ARRAY DO QUE PROCESSADORES/THREADS
            const uint o = __atomic_add_fetch(&node->oCycle, 1, __ATOMIC_ACQUIRE) % O_PAIRS_DYNAMIC;
                                               node->oVersions[o] = BE64(pkt->p[1 + P__VER]) & 0xFF;
                                        memcpy(node->oKeys[o], keys, sizeof(keys));
                             __atomic_store_n(&node->oIndex,   o,       __ATOMIC_RELAXED);
                             __atomic_store_n(&node->rcounter, p_rcounter, __ATOMIC_RELEASE);

            skel = &path->skel;

        } elif (__atomic_load_n(&path->rcounter, __ATOMIC_SEQ_CST) == COUNTER_LISTENING) {
            // SYN

#if 0// TODO:
            uint synCtr;
            do {
                if ((synCtr = __atomic_load_n(&path->synCtr, __ATOMIC_RELAXED)) == 0)
                    return TOO_MANY_SYNS;
            } while (!__atomic_compare_exchange_n(&path->synCtr, synCtr, synCtr - 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
#endif

            // a cada keeper interval:
            // __atomic_add_n(&path->synCtr, path->synLimit - __atomic_load_n(&path->synCtr, __ATOMIC_RELAXED), __ATOMIC_RELAXED);

            // NESTE CASO, LEARN O PATH EM UM PACOTE TEMPORARIO
            // NESTE CASO, NAO APRENDE KEYS E NEM COUNTERS
            in_discover(path, iskb, &skel_);

            skel = &skel_;

        } else
            // SYN
            return PSTATS_I_PING_SYN_NOT_LISTENING;

        ASSERT(skel->x.src  == BE16(nodeSelf));
        ASSERT(skel->x.dst  == BE16(path->nid));
        ASSERT(skel->x.path == BE8(path->pid));

        // AGORA ENVIA O PONG
        uint s;

        skb_s* const oskb = alloc_skb(64 + sizeof(pkt_s) + sizeof(u64) + PONG_SIZE + 64, GFP_ATOMIC);

        if (oskb) {

            // TODO: USA O SKB_DATA ALIGNED
            u64* const pong = SKB_DATA(oskb) + 64 + sizeof(pkt_s) + sizeof(u64);

            for_count (i, PONG_WORDS_N) {
                pong[i] += random64(p_rcounter);
            }   pong[P__CTR] = BE64(__atomic_load_n(&node->lcounter, __ATOMIC_RELAXED));

            pkt_encapsulate(node, O_PAIR_PING, p_rcounter, skel, oskb, pong, PONG_SIZE);

            oskb->ip_summed = CHECKSUM_NONE;

            if (dev_queue_xmit(oskb))
                 s = PSTATS_O_PONG_FAILED;
            else s = PSTATS_O_PONG_OK;
        }   else s = PSTATS_O_PONG_SKB_FAILED;

        // NOTE: WE WILL INFORM THE TOTAL SIZE SENT THROUGHT THE PHYSICAL INTERFACE
        atomic_add(&path->pstats[s].bytes, skel->hsize + sizeof(u64) + PONG_SIZE);
        atomic_inc(&path->pstats[s].count);

        return PSTATS_I_PING_GOOD;
    }

    return PSTATS_I_NOT_PING_OR_PONG;
}

// TODO: FIXME: PROTECT THE REAL SERVER TCP PORTS SO WE DON'T NEED TO BIND TO THE FAKE INTERFACE
int in (skb_s* const skb) {

    uint stat; volatile stat_s* _stat;

    if (skb_linearize(skb))
        ret_dev(DSTATS_I_NON_LINEAR);

    const void* hdr;

    void*       ptr = SKB_NETWORK(skb);
    void* const end = SKB_TAIL(skb);

    //
    uint proto = skb->protocol;

    // NOTE: FICAR DE OLHO NO QUE O skb_vlan_untag() FAZ
    if (proto == BE16(ETH_P_8021Q)
     || proto == BE16(ETH_P_8021AD)) {
        const hdr_vlan_s* const vlan = ptr;
        if ((ptr += sizeof(*vlan)) > end)
            ret_dev(DSTATS_I_INCOMPLETE);
        proto = vlan->proto;
    }

    if (proto == BE16(ETH_P_PPP_SES)) {
        const hdr_ppp_s* const ppp = ptr;
        if ((ptr += sizeof(*ppp)) > end)
            ret_dev(DSTATS_I_INCOMPLETE);
        proto = ppp->proto;
    }

    switch (proto) {
        case BE16(PPP_PROTO_IP4):
        case BE16(ETH_P_IP):
            hdr = ptr + offsetof(hdr_ip4_s, proto);
            proto = sizeof(hdr_ip4_s);
            break;
        case BE16(PPP_PROTO_IP6):
        case BE16(ETH_P_IPV6):
            hdr = ptr + offsetof(hdr_ip6_s, proto);
            proto = sizeof(hdr_ip6_s);
            break;
        case BE16(ETH_P_XGW):
            goto _is_xgw;
        case BE16(ETH_P_ARP):
            // TODO:
            goto _not_xgw;
        case BE16(ETH_P_PPP_DISC):
            goto _not_xgw;
        case BE16(0xfffA): // This.is.loop.detect.frame.se
        case BE16(0x893A): // ..ALCL
            ret_dev(DSTATS_I_FILTERED);
        default:
#if 1
            printk("XGW: UNKNOWN SKB PROTOCOL: 0x%04X\n", BE16(proto));
#endif
            ret_dev(DSTATS_I_UNKNOWN);
    }

    // PTR POINTS TO IP
    // HDR POINTS TO IP PROTOCOL
    // PROTO IS IP SIZE

    if ((ptr += proto) > end)
        ret_dev(DSTATS_I_INCOMPLETE);

    switch (BE8(*(u8*)hdr)) {
        case IPPROTO_UDP:
            proto = sizeof(hdr_udp_s);
            break;
        case IPPROTO_TCP:
            proto = sizeof(hdr_tcp_s);
            break;
        case IPPROTO_XGW:
            goto _is_xgw;
        default:
            goto _not_xgw;
    }

    // PTR POINTS TO TRANSPORT
    // PROTO IS TRANSPORT SIZE

    hdr = ptr;

    if ((ptr += proto) > end)
        ret_dev(DSTATS_I_INCOMPLETE);

    if (!ports_is_enabled(BE16(((u16*)hdr)[1])))
        goto _not_xgw;

_is_xgw:

    if ((ptr += sizeof(hdr_x_s)) > end)
        ret_dev(DSTATS_I_INCOMPLETE);

    // AGORA SABE ONDE COMECA O PKT
    pkt_s* const pkt = ptr - sizeof(pkt_s);

    //
    const uint nid = BE16(pkt->x.src);

    ASSERT(nid < NODES_N);

    if (nid == nodeSelf)
        ret_dev(DSTATS_I_FROM_SELF);

    if (BE16(pkt->x.dst) != nodeSelf)
        ret_node(NSTATS_I_FORWARD);

    //
    if (!(xgw->flags & IFF_UP))
        ret_dev(DSTATS_I_DOWN);

    node_s* const node = nodes_get_unlocked(nid);

    if (node == NULL)
        ret_node(NSTATS_I_INEXIST);

    if (node_is_off(node))
        ret_node(NSTATS_I_DISABLED);

    const uint pid = BE8(pkt->x.path);

    if (pid >= PATHS_N)
        ret_node(NSTATS_I_PATH_INVALID);

    if (!(__atomic_load_n(&node->ipaths, __ATOMIC_SEQ_CST) & IPATH(pid)))
        ret_path(PSTATS_I_DISABLED);

    const uint size = BE16(pkt->x.dsize);

    if (size < XGW_PAYLOAD_MIN)
        ret_path(PSTATS_I_SIZE_SMALL);

    if ((PTR(&pkt->p[1]) + size) > end)
        ret_path(PSTATS_I_SIZE_TRUNCATED);

    // TODO: SIMPLIFICAR: decrypt() sem o argumento i, ler o i no decrypt(), assinar com 0 no ping/pong
    const uint i = BE8(pkt->x.version);

    // PRIVACY
    const u64 p_lcounter = pkt_decrypt(node, i, pkt, size);

    if (i == I_PAIR_PING)
        // PING/PONG
        ret_path(in_pp(node, skb, pkt, size, p_lcounter));

    // NORMAL PACKET

    // O SIGN É O TIMESTAMP
    // REPLAY/CORRUPTION/FORGING/EXPIRATION PROTECTION
    // NOTE: LEMBRANDO QUE O TEMPO TODO AMBOS FICAM AJUSTANDO O NODE->DIFF,
    //       ENTAO NAO DA PARA LEVAR AO PE DA LETRA ESSES TIMES
    // NOTE: O PACOTE PODE TER LEVADO UM TEMPO A CHEGAR, SER PROCESSADO ETC
    const u64 node_lcounter = __atomic_load_n(&node->lcounter, __ATOMIC_RELAXED);

    if (ABS_DIFF(node_lcounter, p_lcounter) > 2)
        ret_path(PSTATS_I_DATA_LCOUNTER_MISMATCH);

    // AVANCA O ALIGNMENT
    void* const orig = PTR(&pkt->p[1]);

    if (BE8(*(u8*)orig) == 0x45) { // TODO:

        // NOTE: AQUI CONSIDERA O IP4 + PORTAS
        if ((orig + sizeof(ip4_s)) > end)
            ret_path(PSTATS_I_DATA_IP4_TRUNCATED);

#ifdef CONFIG_XGW_GATEWAY_TCP_PROXY
        ip4_s* const ip = orig;

        if (ip->proto == BE8(IPPROTO_TCP)) {
            // TODO: SE FOR SYN/SYN-ACK, ADJUST MSS
            if (BE32(ip->saddr ^ ip->daddr) >> 8) { // TODO:
                // XGW -> INTERNET
                // WILL BE TREATED AS SELF, SO NO NEED FOR TCP CHECKSUM
                skb->mark  = XGW_TCP_PROXY_MARK_4 | BE16(ip->dport);
                ip->dport  = BE16(CONFIG_XGW_GATEWAY_TCP_PROXY_PORT);
            }
        }
#endif

        skb->protocol = BE16(ETH_P_IP);

    } else { ASSERT((BE8(*(u8*)orig) >> 4) == 6);

        if ((orig + sizeof(ip6_s)) > end)
            ret_path(PSTATS_I_DATA_IP6_TRUNCATED);

#ifdef CONFIG_XGW_GATEWAY_TCP_PROXY
        ip6_s* const ip = orig;

        if (ip->proto == BE8(IPPROTO_TCP)) {
            // TODO: SE FOR SYN/SYN-ACK, ADJUST MSS
            if (BE64(ip->saddr[0] ^ ip->daddr[0])) { // TODO:
                // XGW -> INTERNET
                // WILL BE TREATED AS SELF, SO NO NEED FOR TCP CHECKSUM
                skb->mark  = XGW_TCP_PROXY_MARK_6 | BE16(ip->dport);
                ip->dport  = BE16(CONFIG_XGW_GATEWAY_TCP_PROXY_PORT);
            }
        }
#endif

        skb->protocol = BE16(ETH_P_IPV6);
    }

    //
    skb->len            = size;
    skb->data           = orig;
    skb->network_header = orig        - SKB_HEAD(skb);
#ifdef NET_SKBUFF_DATA_USES_OFFSET // SKB TRIM QUE NEM É FEITO NO ip_rcv_core()
    skb->tail           = orig + size - SKB_HEAD(skb);
#else
    skb->tail           = orig + size;
#endif
 // skb->mac_header
 // skb->mac_len
#if 0
    skb->ip_summed      = CHECKSUM_COMPLETE;
    skb->csum_valid     = 1;
    skb->csum_complete_sw = 1;
#else // LIKE WIREGUARD
    skb->ip_summed      = CHECKSUM_UNNECESSARY;
    skb->csum_level     = ~0;
#endif
    skb->dev            = xgw;
    skb->pkt_type       = PACKET_HOST; // WE MAY BE RECEIVING VIA MULTICAST/BROADCAST
    // TODO: ON OUT: skb->type = PACKET_BROADCAST | PACKET_MULTICAST | PACKET_OTHERHOST | PACKET_OUTGOING

    stat = PSTATS_I_DATA_GOOD;

_ret_path: _stat = node->pstats[pid]; goto _ret;
_not_xgw:   stat = DSTATS_I_NOT_XGW; // JUST SOME PACKET, TRAVELING AROUND THE WORLD IN 80 HOPS
_ret_dev:  _stat = dstats;            goto _ret;
_ret_node: _stat = nstats[nid];
_ret:

    atomic_inc(&_stat[stat].count);
    atomic_add(&_stat[stat].bytes, skb->len);

    // NOTE QUE TODOS OS STATS PASS SAO 0
    return stat;
}

// TODO: IKEYS_PING, IKEYS_PONG,
// TODO: OKEYS_PING, OKEYS_PONG,

// TODO: O CLIENTE SO ACEITA PONGS VALIDADOS
// TODO: O CLIENTE SO ACEITA PINGS VALIDADOS
// TODO: AO RECEBER UM PING, O CLIENTE JAMAIS COPIA O CABEÇALHO DE CHEGADA

