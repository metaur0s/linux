
// ON path->rtime
#define RTIME_LISTENING   0
#define RTIME_ACCEPTING   1
#define RTIME_CONNECTING  2
#define RTIME_ESTABLISHED RTIME_MIN

#define RTIME_MIN ((u64)8192)
#define RTIME_MAX ((u64)(8ULL*12*31*24*3600*1000))

#define COUNTER_SYN_MIN ((u64)8)
#define COUNTER_SYN_MAX ((~(u64)0) - 32)

#if 0
static inline int in_pp (node_s* const node, path_s* const path, const u64 counter, skb_s* const iskb, const pkt_s* const pkt, const uint size, const u64 p_counter) {

    if (p_counter == path->counterSyn) {
        // SYN

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

    // NOTE: WHEN SETTING A COUNTER-SYN, IT MUST BE > COUNTER_SYN_MIN
    // NOTE: WHEN SETTING A COUNTER-SYN, IT MUST BE > COUNTER_SYN_MAX

    if (i >= I_KEYS_DYNAMIC && size != PING_SIZE)
        // BAD SIZE FOR A PING PACKET
        ret_path(PSTATS_I_PING_BAD_SIZE);

    u16 latency = atomic_get(&path->latency);
    s64 tdiff   = atomic_get(&path->tdiff);
    u64 rtime   = atomic_get(&path->rtime);

    if (rtime >= RTIME_ESTABLISHED) {
        if (i == I_KEY_SYN)
            // ESTABLISHED RECEBE TUDO MENOS SYN
            ret_path(PSTATS_I_ESTABLISHED_SYN);
    } elif (rtime == RTIME_CONNECTING) {
        if (i != I_KEY_PONG)
            // CONNECTING SO RECEBE PONGS
            ret_path(PSTATS_I_NOT_PONG);
    } elif (rtime == RTIME_LISTENING) {
        if (i != I_KEY_SYN &&
            i != I_KEY_PING)
            // LISTENING SO RECEBE SYN E PING
            ret_path(PSTATS_I_NOT_SYN_OR_PING);
    } else { // RACED WITH AN ACCEPTING
        ASSERT(rtime == RTIME_ACCEPTING);
        ret_path(PSTATS_I_WHILE_ACCEPTING);
    }

    if (i == I_KEY_SYN) {
        if (p_ltime != path->syn)
            // ELE NAO CONHECE NOSSO CODIGO
            ret_path(PSTATS_I_LTIME_NOT_SYN);
    } elif (ABS_DIFF(now, p_ltime) > 400)
        // ELE NAO CONHECE NOSSO TIME
        ret_path(PSTATS_I_LTIME_MISMATCH);

    // DECRYPT
    if (pkt_decrypt(node, i, pkt, size) != hash)
        // CORRUPT
        ret_path(PSTATS_I_HASH_MISMATCH);

    // IS A EXPECTED TYPE FOR OUR STATUS
    // IS AUTHENTIC (hash)
    // IS SYNCED (p_ltime)

    if (i >= I_KEY_PING) {

        // HIS RAW TIME
        u64 p_rtime = BE64(PKT_PING_TIME(pkt));

        if (p_rtime < RTIME_MIN
         || p_rtime > RTIME_MAX)
            // INVALID RTIME
            ret_path(PSTATS_I_RTIME_INVALID);

        if (rtime >= RTIME_ESTABLISHED){
            // JA CONHEÇO O TIME DELE, O DIFF E O LATENCY
            if (p_rtime <= rtime)
                // HIS RAW TIME CANNOT GO DOWN OR REPEAT
                ret_path(PSTATS_I_RTIME_BACKWARDS);
            // COMPARA O TIME QUE ELE DIZ TER, COM O TIME (APROXIMADO) QUE SABEMOS QUE ELE TEM
            const s64 diff =
                (p_rtime + latency) // O RELOGIO DELE COMO ELE DIZ QUE ESTA (APROXIMADO)
                	-
             	LTIME_TO_RTIME(now, tdiff) // O RELOGIO DELE COMO ELE DEVERIA SER (APROXIMADO)
            ; // A IMPRECISÃO NÃO PODE SER TÃO GRANDE ASSIM:
            if (diff > 2000) // PEER AFOBADO
                ret_path(PSTATS_I_RTIME_SKEW_UP);
            if (diff < -2000) // PEER LESADO
                ret_path(PSTATS_I_RTIME_SKEW_DOWN);
        }

        // FAZ ISSO PRIMEIRO ANTES DE LIBERAR O PATH PARA ENVIAR
        // NOTE: A CADA INTERVALO SAO ENVIADOS PINGS POR TODOS OS PATHS,
        //       ENTAO PODE ACABAR TENDO RACE CONDITION AQUI.
        // POR PRECAUCAO O IDEAL É TER MAIS ENTRADAS NA ARRAY DO QUE PROCESSADORES/THREADS
        const uint o = __atomic_add_fetch(&node->oCycle, 1, __ATOMIC_ACQUIRE) % O_KEYS_DYNAMIC;
                                           node->oVersions[o] = BE8(ping->ver);
                                    memcpy(node->oKeys[o], K, sizeof(K));
                         __atomic_store_n(&node->oIndex,   o,          __ATOMIC_RELAXED);
                         __atomic_store_n(&node->rcounter, p_rcounter, __ATOMIC_RELEASE);

        if (i == I_KEY_PONG) {
            // CONNECTING / ESTABLISHED

            // TODO: LIMITAR A QUANTIDADE DE SYNS RECEBIVEIS A CADA KEEPER INTERVAL

            if (!__atomic_compare_exchange_n(&path->pingSent, &p_ltime, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
                ret_path(PSTATS_I_PONG_RACED);

            // CONFIRMOU QUE ESTA RESPOSTA SE REFERE AO ULTIMO PING ENVIADO, E LIMPOU ELE: NAO VAI ACEITAR OUTRO

            const u16 latency = (latency + (now - p_ltime)/2) / 2;

            // ELE NOS MANDOU O TIME DELE DE QUANDO ELE RECEBEU.
            // MAS CONSIDERA O TIME QUE ELE TINHA QUANDO ENVIAMOS.
            // E ENTAO PEGA A COMPARAÇÃO ENTRE *LOCAL TIME WHEN I SENT* COM *REMOTE TIME WHEN I SENT*
            const s64 tdiff = (tdiff + LTIME_DIFF_RTIME(p_ltime, p_rtime - latency)) / 2;

            // ESTE AQUI DEVERIA SER COMPARE, EXCHANGE, MAS:
            // SÓ PODE ACONTECER UM RACE SE ENTRARMOS NESTE BLOCO E AO MESMO TEMPO O KEEPER GERAR UM NOVO path->pingSent,
            // E A RESPOSTA VIR TELEPATICAMENTE E SER PROCESSADA AO MESMO TEMPO.
            // O RESULTADO É QUE PODERIAMOS ESTAR ESCREVENDO ESTE P_RTIME ANTIGO POR CIMA DO NOVO.
            // MAS DE QUALQUER JEITO, O NOVO É MAIOR DO QUE O ANTERIOR A ESTE, COMO CHECAMOS ACIMA.
            __atomic_store_n(&path->rtime, p_rtime, __ATOMIC_RELAXED);
            __atomic_store_n(&path->tdiff, tdiff, __ATOMIC_RELAXED);
            __atomic_store_n(&path->rtt, rtt, __ATOMIC_RELAXED);
            __atomic_store_n(&path->pongReceived, now, __ATOMIC_SEQ_CST); // <-- THIS MOVES FROM CONNECTING -> ESTABLISHED

            // LEARN HIS INPUT KEYS (MY OUTPUT KEYS)
            u64 K[K_LEN];

            secret_derivate_random_as_key(node->secret, ping->rnd, K);

            // NOW APPLY

            ret_path(PSTATS_I_PONG_OK);
        }

        // THIS IS A PING
        pkt_s* skel; pkt_s temp_skel;

        if (rtime == RTIME_LISTENING) {
            // LISTENING

            if (i == I_KEY_PING) {
                // SYN-ACK

                if (!__atomic_compare_exchange_n(&path->rtime, &rtime, RTIME_ACCEPTING, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
                    // LOCK FAILED
                    ret_path(PSTATS_I_ACCEPT_RACED);

                // LOCKED - NINGUEM PODE TOCAR NO PATH
                // LEARN ON PATH
                skel = &path->skel;
            } else
                // SYN
                // LEARN O PATH EM UM HEADER TEMPORARIO
                // NAO APRENDE KEYS E NEM COUNTERS
                skel = &temp_skel;

            in_discover(path, skb, skel);

            // OBS.: AQUI O PATH AINDA PODE ESTAR LOCKED
            if (skel != &temp_skel) {
                // UNLOCK E LIBERA O KEEPER
                __atomic(&path->rcounterUpdated, get_jiffies64());
                __atomic(&path->rtime, &rtime, p_rcounter);
            }
        } else
            // ESTABLISHED
            skel = &path->skel;

        // RESPONDE COM UM PONG

        // TODO: AQUI PELO MENOS PODEMOS ALINHAR - PTR(((uintptr_t)SKB_DATA(skb) + sizeof(u64) - 1) % sizeof(u64))
        ping_s* const ping = SKB_DATA(skb) + 64 + PKT_SIZE + PKT_ALIGN_SIZE;

        // A CADA PING A INPUT KEY MAIS ANTIGA É EXPIRADA
        const uint i = node->iCycle = ((uint)node->iCycle + 1) % I_KEYS_DYNAMIC;

        // GERA AS KEYS
        random64_n(PTR(ping), PING_RANDOMS_N, SUFFIX_ULL(CONFIG_XGW_RANDOM_PING));

        // SEM ATOMICITY/BARRIER POR QUE O PEER SO VAI REFERENCIAR ESSE NOSSO INPUT INDEX QUANDO ELE RECEBER
        secret_derivate_random_as_key(node->secret, ping->rnd, node->iKeys[i]);

        pkt->time = BE64(p_rtime);

        PKT_PING_VER(pkt) &= BE64(~((u64)0xFF));
        PKT_PING_VER(pkt) |= BE64(i); // OVERWRITE WITH THE VERSION
        PKT_PING_TIME(pkt) = BE64(now);

        ret_path(PSTATS_I_PING_OK);
    }

    // REPLAY/CORRUPTION/FORGING/EXPIRATION PROTECTION
    // NOTE: LEMBRANDO QUE O TEMPO TODO AMBOS FICAM AJUSTANDO O NODE->DIFF,
    //       ENTAO NAO DA PARA LEVAR AO PE DA LETRA ESSES TIMES
    // NOTE: O PACOTE PODE TER LEVADO UM TEMPO A CHEGAR, SER PROCESSADO ETC

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
