
enum PPP_PROTO {
    PPP_PROTO_IP4   = 0x0021,
    PPP_PROTO_IP6   = 0x0057,
    PPP_PROTO_LCP   = 0xC021, // Protocol: Link Control Protocol (0xc021)
    PPP_PROTO_PAP   = 0xC023, // Protocol: Password Authentication Protocol (0xc023)
    PPP_PROTO_IPCP4 = 0x8021, // Protocol: Internet Protocol Control Protocol (0x8021)
    PPP_PROTO_IPCP6 = 0x8057, // Protocol: IPv6 Control Protocol (0x8057)
    PPP_PROTO_XGW   = 0x2562,
};

// ASSERT: IPPROTO_UDP != PPP_PROTO_IP4
// ASSERT: IPPROTO_UDP != PPP_PROTO_IP6
BUILD_ASSERT(IPPROTO_UDP != ETH_P_IP);
BUILD_ASSERT(IPPROTO_UDP != ETH_P_IPV6);

// ASSERT: IPPROTO_TCP != PPP_PROTO_IP4
// ASSERT: IPPROTO_TCP != PPP_PROTO_IP6
BUILD_ASSERT(IPPROTO_TCP != ETH_P_IP);
BUILD_ASSERT(IPPROTO_TCP != ETH_P_IPV6);

// ON path->rtime
#define PATH_RCOUNTER_LISTENING  0
#define PATH_RCOUNTER_ACCEPTING  1
#define PATH_RCOUNTER_CONNECTING 2

#define COUNTER_SYN_MIN ((u64)8)
#define COUNTER_SYN_MAX ((~(u64)0) - 32)

#define XGW_TIME_MIN ((u64)32)
#define XGW_TIME_MAX ((~(u64)0) - 4*12*31*24*3600)

static inline void in_discover (const path_s* const path, const skb_s* const skb, pkt_s* const skel) {

    ASSERT(path->info & P_SERVER);

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

#if 0
static inline int in_pp (node_s* const node, path_s* const path, const u64 counter, skb_s* const iskb, const pkt_s* const pkt, const uint size, const u64 p_counter) {

    u64 p_counter_ = p_counter;

    if (size == PONG_SIZE) {
        // NOTA: O PONG TEM QUE SER ENVIADO COM O COUNTER QUE RECEBEU NO PING, NAO IMPORTA SE SOU CLIENTE OU SERVIDOR.
        if (__atomic_compare_exchange_n(&path->received, &p_counter_, get_jiffies_64(), 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
            // SUCCESS
            return PSTATS_I_PONG_GOOD;
        // PONG REPETIDO, OU ATRASADO
        return PSTATS_I_PONG_COUNTER_MISMATCH;
    }

    if (size != PING_SIZE)
        return PSTATS_I_NOT_PING_OR_PONG;

    pkt_s* skel; pkt_s skel_;

    //if (p_rcounter <= COUNTER_CONNECTING)
        // HIS COUNTER IS INVALID
        // CANNOT BECAME LISTENING/DISCOVERING/CONNECTING
        //return PSTATS_I_PING_RCOUNTER_INVALID;

    if (path->counter == 0) {
        // I AM A SERVER, WAITING FOR A SYN

        if (p_session = path->counterSyn) {
            // THIS PACKET IS NOT A SYN
            return PSTATS_I_COUNTER_NOT_SYN;
    }

    if (p_counter == path->counterSyn) {
        // SYN

        if (__atomic_compare_exchange_n(&path->counter, &path->counterSyn, p_counter_, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
            // WE RECEIVED A SYN PACKET BUT WE ARE NOT LISTENING
            //return PSTATS_I_PING_SYN_NOT_LISTENING;

        // TODO: LIMITAR A QUANTIDADE DE SYNS RECEBIVEIS A CADA KEEPER INTERVAL

        // NESTE CASO, LEARN O PATH EM UM PACOTE TEMPORARIO
        // NESTE CASO, NAO APRENDE KEYS E NEM COUNTERS
        in_discover(path, iskb, &skel_);

        skel = &skel_;

    } else { // NOTE: THE SIGN HE SENT IS FROM THE NODE->LCOUNTER; IT WOULD BE CORRECT EVEN WITHOUT HANDSHAKE, BUT KEEPER WON'T SEND WITHOUT ONE

        // TODO: LIMITAR A QUANTIDADE DE PINGS RECEBIVEIS A CADA KEEPER INTERVAL
        //  NA VERDADE, SO RECEBE UM PING A CADA INTERVAL

        u64 node_lcounter = __atomic_load_n(&node->lcounter, __ATOMIC_RELAXED);
        u64 path_rcounter = __atomic_load_n(&path->rcounter, __ATOMIC_RELAXED); // COUNTER DELE, DO ULTIMO PING QUE ELE NOS MANDOU

        // NOT A SYN; HE MUST KNOW OUR COUNTER
        // NOTE: CONSIDERAR CLOCK SKELS E INTERVALOS ENTRE PINGS
        if (ABS_DIFF(node_lcounter, p_ltime) > 2)
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
                // a) WE ARE THE SERVER, AND THIS IS THE FIRST PING THE CLIENT SENT WITH OUR COUNTER
                // DISCOVER THE CLIENT PATH
                    in_discover(path, iskb, &path->skel);
                // DISCOVER THE CLIENT COUNTER
                    __atomic_store_n(&node->rcounter, p_rcounter, __ATOMIC_RELAXED);
                // START SENDING PINGS
                    __atomic_store_n(&path->rcounter, p_rcounter, __ATOMIC_RELEASE);
            } else
                // b) RACED COM OUTRO ACCEPT
                return PSTATS_I_PING_RACED;
        }

        u64 K[K_LEN];

        secret_derivate_random_as_key(node->secret, ping->rnd, K);

        // FAZ ISSO PRIMEIRO ANTES DE LIBERAR O PATH PARA ENVIAR
        // NOTE: A CADA INTERVALO SAO ENVIADOS PINGS POR TODOS OS PATHS,
        //       ENTAO PODE ACABAR TENDO RACE CONDITION AQUI.
        // POR PRECAUCAO O IDEAL É TER MAIS ENTRADAS NA ARRAY DO QUE PROCESSADORES/THREADS
        const uint o = __atomic_add_fetch(&node->oCycle, 1, __ATOMIC_ACQUIRE) % O_KEYS_DYNAMIC;
                                           node->oVersions[o] = BE8(ping->ver);
                                    memcpy(node->oKeys[o], K, sizeof(K));
                         __atomic_store_n(&node->oIndex,   o,          __ATOMIC_RELAXED);
                         __atomic_store_n(&node->rcounter, p_rcounter, __ATOMIC_RELEASE);

        skel = &path->skel;
    }

    // AGORA ENVIA O PONG
    uint s;

    skb_s* const oskb = alloc_skb(64 + PKT_SIZE + PKT_ALIGN_SIZE + PONG_SIZE + 64, GFP_ATOMIC);

    if (oskb) {

        // TODO: USA O SKB_DATA ALIGNED
        void* const pong = SKB_DATA(oskb) + 64 + PKT_SIZE + PKT_ALIGN_SIZE;

        random64_n(pong, PONG_RANDOMS_N, p_rcounter);

        // TODO: O ALIGN COM RANDOM TEM QUE SER COLOCADO FORA DO ENCAPSULATE, POIS NO CASO DO PING/PONG NAO VAMOS USAR
        pkt_encapsulate(node, O_KEY_PING, p_rcounter, skel, oskb, pong, PONG_SIZE);

        oskb->ip_summed = CHECKSUM_NONE;

        if (dev_queue_xmit(oskb))
             s = PSTATS_O_PONG_FAILED;
        else s = PSTATS_O_PONG_OK;
    }   else s = PSTATS_O_PONG_SKB_FAILED;

    // NOTE: WE WILL INFORM THE TOTAL SIZE SENT THROUGHT THE PHYSICAL INTERFACE
    atomic_add(&path->pstats[s].bytes, skel->hsize + PKT_ALIGN_SIZE + PONG_SIZE);
    atomic_inc(&path->pstats[s].count);

    return PSTATS_I_PING_GOOD;
}
#endif

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
    switch (proto) {
        case BE16(ETH_P_8021Q):
        case BE16(ETH_P_8021AD): {
            const hdr_vlan_s* const vlan = ptr;
            if ((ptr += sizeof(*vlan)) > end)
                ret_dev(DSTATS_I_INCOMPLETE);
            proto = vlan->proto;
        } break;
    }

    switch (proto) {

        case BE16(ETH_P_PPP_SES): {
            const hdr_ppp_s* const ppp = ptr;
            if ((ptr += sizeof(*ppp)) > end)
                ret_dev(DSTATS_I_INCOMPLETE);
            switch (ppp->proto) {
                case BE16(PPP_PROTO_IP4):
                    hdr = ptr + offsetof(hdr_ip4_s, proto);
                    proto = sizeof(hdr_ip4_s);
                    break;
                case BE16(PPP_PROTO_IP6):
                    hdr = ptr + offsetof(hdr_ip6_s, proto);
                    proto = sizeof(hdr_ip6_s);
                    break;
                case BE16(PPP_PROTO_XGW):
                    goto _is_xgw;
                default:
                    goto _not_xgw;
            }
        } break;

        case BE16(ETH_P_IP):
            hdr = ptr + offsetof(hdr_ip4_s, proto);
            proto = sizeof(hdr_ip4_s);
            break;
        case BE16(ETH_P_IPV6):
            hdr = ptr + offsetof(hdr_ip6_s, proto);
            proto = sizeof(hdr_ip6_s);
            break;
        case BE16(ETH_P_XGW):
            goto _is_xgw;
        default:
            goto _not_xgw;
    }

    // PTR POINTS TO IP
    // HDR POINTS TO IP PROTOCOL
    // PROTO IS IP SIZE

    if ((ptr += proto) > end)
        ret_dev(DSTATS_I_INCOMPLETE);

    proto = *(u8*)hdr;

    switch (proto) {
        case BE8(IPPROTO_UDP):
            proto = sizeof(hdr_udp_s);
            break;
        case BE8(IPPROTO_TCP):
            proto = sizeof(hdr_tcp_s);
            break;
        case BE8(IPPROTO_XGW):
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

    const uint nid      = BE16 (pkt->x.src);
    const uint pid      = BE8  (pkt->x.path);
    const uint size     = BE16 (pkt->x.dsize);
    const uint i        = BE8  (pkt->x.version);
          u64  p_ltime  = BE64 (pkt->x.time);
    const u64  hash     = BE64 (pkt->x.hash);

    ASSERT(nid < NODES_N);

    if (nid == nodeSelf)
        ret_dev(DSTATS_I_FROM_SELF);

    if (BE16(pkt->x.dst) != nodeSelf)
        ret_node(NSTATS_I_FORWARD);

    // TODO: UMA FLAG GLOBAL XGW IS DISABLED
    // TODO: UMA STAT GLOBAL XGW IN IS DISABLED
    // TODO: UMA STAT GLOBAL XGW OUT IS DISABLED

    node_s* const node = nodes_get_unlocked(nid);

    if (node == NULL)
        ret_node(NSTATS_I_INEXIST);

    if (node_is_off(node))
        ret_node(NSTATS_I_DISABLED);

    if (!(node->dev->flags & IFF_UP))
        ret_dev(NSTATS_I_DOWN);

    if (pid >= PATHS_N)
        ret_node(NSTATS_I_PATH_INVALID);

    if (!(__atomic_load_n(&node->ipaths, __ATOMIC_SEQ_CST) & IPATH(pid)))
        ret_path(PSTATS_I_DISABLED);

    if (size < XGW_PAYLOAD_MIN)
        ret_path(PSTATS_I_SIZE_SMALL);

    if ((PTR(pkt) + PKT_SIZE + PKT_ALIGN_SIZE + size) > end)
        ret_path(PSTATS_I_SIZE_TRUNCATED);

    path_s* const path = &node->paths[pid];

    const u64 now = get_current_ms();

    // NOTE: WHEN SETTING A COUNTER-SYN, IT MUST BE generated > COUNTER_SYN_MIN
    // NOTE: WHEN SETTING A COUNTER-SYN, IT MUST BE generated > COUNTER_SYN_MAX

    // NOTE: WHEN SETTING A COUNTER, IT MUST BE ABS_DIFF(generated, path->counterSyn) > 32
    // NOTE: WHEN SETTING A COUNTER, IT MUST BE generated > XGW_TIME_MIN
    // NOTE: WHEN SETTING A COUNTER, IT MUST BE generated < XGW_TIME_MAX

    if (i >= I_KEYS_DYNAMIC && size != PING_SIZE)
        // BAD SIZE FOR A PING PACKET
        ret_path(PSTATS_I_PING_BAD_SIZE);

    u64 rtime = atomic_get(&path->rtime);

    if (rtime >= PATH_RCOUNTER_CONNECTING) {
        if (rtime == PATH_RCOUNTER_CONNECTING && i != I_KEY_PONG)
            // CONNECTING SO RECEBE PONGS
            ret_path(PSTATS_I_NOT_PONG);
        if (ABS_DIFF(now, p_ltime) > 400) // TODO: O ENVIADOR OU O RECEBEDOR TEM QUE INCLUIR O LATENCY NO pkt->tstamp?
            // ELE NAO CONHECE NOSSO TIME
            ret_path(PSTATS_I_LTIME_MISMATCH);
    } elif (rtime == PATH_RCOUNTER_LISTENING) {
        if (i != I_KEY_PING)
            // LISTENING SO RECEBE PINGS
            ret_path(PSTATS_I_NOT_PING);
        if (ABS_DIFF(now, p_ltime) > 400 && p_ltime != path->syn)
            // LISTENING SO RECEBE COM PKT->TSTAMP +/- now | SYN
            ret_path(PSTATS_I_LTIME_MISMATCH);
    } else { // RACED WITH AN ACCEPTING
        ASSERT(rtime == PATH_RCOUNTER_ACCEPTING);
        ret_path(PSTATS_I_WHILE_ACCEPTING);
    }

    // DECRYPT
    if (pkt_decrypt(node, i, pkt, size) != hash)
        // CORRUPT
        ret_path(PSTATS_I_HASH_MISMATCH);

    // IS A EXPECTED TYPE FOR OUR STATUS
    // IS AUTHENTIC (hash)
    // IS SYNCED (p_ltime)

    if (i >= I_KEY_PING) {

        u64 p_rtime = BE64(PKT_PING_TIME(pkt));

        if (!(XGW_TIME_MIN <= p_rtime && p_rtime <= XGW_TIME_MAX))
            // INVALID RTIME
            ret_path(PSTATS_I_RTIME_INVALID);

        if ((rtime >= p_rtime) && (rtime - p_rtime) > 500)
            // NOTE: JA SEI QUE O RTIME É CONHECIDO AQUI, POIS SE NAO FOSSE SERIA 0, 1 ETC,
            //  E PARA SER SER MENOR DO QUE ISSO, P_RTIME TERIA DE SER INVALIDO, E NAO É POIS JA CHECOU
            // ATRASADO / REPEATED
            ret_path(PSTATS_I_RTIME_BACKWARDS);

        if (i == I_KEY_PONG) {
            // CONNECTING / ESTABLISHED

            if (__atomic_compare_exchange_n(&path->rtime, &rtime, p_rtime, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                __atomic_compare_exchange_n(&path->pingSent, &p_ltime, 0, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
                u64 rtt = (atomic_get(&path->rtt) + (now - p_ltime)) / 2;
                u64 tdiff = (atomic_get(&path->tdiff) + ((s64)p_ltime - (s64)(p_rtime + rtt/2))) / 2;
                __atomic_store_n(&path->rtt, rtt, __ATOMIC_RELAXED);
                __atomic_store_n(&path->tdiff, tdiff, __ATOMIC_RELAXED);
                __atomic_store_n(&path->pongReceived, now, __ATOMIC_RELAXED); // <-- THIS MOVES FROM CONNECTING -> ESTABLISHED
            }

            ret_path(PSTATS_I_RTIME_BACKWARDS); //goto pong_ok;
        }

        // THIS IS A PING
        pkt_s* skel; pkt_s temp_skel;

        if (rtime == PATH_RCOUNTER_LISTENING) {
            // LISTENING

            if (p_ltime == path->syn) // TODO: TEM QUE TER UM I_KEY_SYN
                // RECEIVED A SYN, LEARN ON TEMP
                skel = &temp_skel;
            elif (__atomic(&path->rtime, &rtime, LOCKA))
                // RECEIVED A ACK, LEARN ON PATH
                // LOCK LISTENING -> ACCEPTING SUCCESSFUL
                skel = &path->skel;
            else
                // RECEIVED A ACK, LEARN ON PATH
                // LOCK LISTENING -> ACCEPTING FAILED
                ret_path(PSTATS_I_RTIME_BACKWARDS); //goto err_raced_ack;

                //
            in_discover(path, skb, skel);

            if (skel == &path->skel) {
                // RECEIVED A ACK, LEARNED ON PATH
                // AGORA LIBERA O KEEPER
                // NOTE: O KEEPER E NINGUEM PODE TOCAR NO PATH ENQUANTO LOCKADO NO MODO ACCEPTING
                __atomic(&path->rcounterUpdated, get_jiffies64());
                __atomic(&path->rtime, &rtime, p_rcounter);
            }
        } else // ESTABLISHED
            skel = &path->skel;

        // RESPONDE O PING DELE COM UM PONG
        pkt->counter = p_rtime;
    //  PKT_PING_VER(pkt) &= BE64(~((u64)0xFF));
    //  PKT_PING_VER(pkt) |= BE64(ver);
        PKT_PING_CTR(pkt) = now;

        ret_path(PSTATS_I_RTIME_BACKWARDS); // goto ping_ok;
    }


    //
    if (pkt_decrypt(node, i, pkt, size) != hash)
        ret_path(PSTATS_I_COUNTER_NOT_SYN); // PSTATS_I_HASH_MISMATCH

    // REPLAY/CORRUPTION/FORGING/EXPIRATION PROTECTION
    // NOTE: LEMBRANDO QUE O TEMPO TODO AMBOS FICAM AJUSTANDO O NODE->DIFF,
    //       ENTAO NAO DA PARA LEVAR AO PE DA LETRA ESSES TIMES
    // NOTE: O PACOTE PODE TER LEVADO UM TEMPO A CHEGAR, SER PROCESSADO ETC

    if (i >= I_KEY_PING) {
        // PING/PONG

    }

    // NORMAL PACKET

    // AVANCA O ALIGNMENT
    void* const orig = PTR(pkt->p + PKT_ALIGN_RANDOMS);

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
    skb->dev            = node->dev;
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
