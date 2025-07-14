
// IT MUST BE NOT INLINED, AS THE WHOLE INTENTION OF SEPARATING IT AS A FUNCTION IS TO MINIMIZE THE IN FUNCTION
// WE DARE TO REDO SOME THINGS HERE, SO IF WE INLINE, THOSE WILL BE SURPLEFUOUS.
static noinline uint in_ping (node_s* const node, const skb_s* const skb, pkt_s* const pkt) {

    pkt_s* skel; pkt_s temp_skel;

    const ping_s* const ping = PKT_DATA(pkt);

    const uint pid  = BE8(pkt->x.path);
    const uint i    = BE8(pkt->x.version);
    const u64 ltime = BE64(pkt->x.time);
    const u64 rtime = BE64(ping->time);

    ASSERT(pid <= PID_MAX);
    ASSERT(i == I_KEY_PING
        || i == I_KEY_PONG
        || i == I_KEY_SYN);
    ASSERT(rtime >= PTIME_MIN);
    ASSERT(rtime <= PTIME_MAX);

    path_s* const path = &node->paths[pid];

    const u64 now = path->mask + get_current_ms();

    ASSERT(now >= PTIME_MIN);
    ASSERT(now <= PTIME_MAX);

    s64 tdiff;

    if (i == I_KEY_SYN) {

        ASSERT(ltime == path->syn);

        // ESTE RTIME NÃO CONSIDERA O ATRASO
        tdiff = LTIME_DIFF_RTIME(now, rtime);

        ASSERT(tdiff >= TDIFF_MIN);
        ASSERT(tdiff <= TDIFF_MAX);

    } else {

        ASSERT(ltime >= PTIME_MIN);
        ASSERT(ltime <= PTIME_MAX);

        // HIS RAW TIME MUST ADVANCE
        // SEPARATE PING AND PONG
        volatile u64* const ptr = &path->pseen[i == I_KEY_PONG];

        u64 seen = atomic_get(ptr);

        ASSERT((seen >= PTIME_MIN &&
                seen <= PTIME_MAX) ||
                seen == 0);

        // CONSIDERA QUE PODE TER PERDIDO ALGUNS PINGS
        if (seen && (rtime - seen) > 49152)
            // BACKWARD / REPEATED / BIG JUMP
            return PSTATS_I_RTIME_MISMATCH;

        if (!__atomic_compare_exchange_n(ptr, &seen, rtime + 1, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            // RACE CONDITION
            return PSTATS_I_RTIME_MISMATCH;

        // TODO: USAR UM VALOR QUE NAO SEJA 0 PARA TDIFFS NAO INICIALIZADOS
        tdiff = __atomic_load_n(&path->tdiff, __ATOMIC_RELAXED);

        ASSERT(tdiff >= TDIFF_MIN);
        ASSERT(tdiff <= TDIFF_MAX);

        tdiff = (
            // CONSIDERA O MEU
            tdiff * (tdiff != 0) +
            // SE NIVELA AO PEER
            // O SYN USA O CODIGO, E O PONG DE UM SYN NAO CONSIDERA O LATENCY; ENTAO SO PODE CONSIDERAR ESTA RELACAO DE UM PING
            LTIME_DIFF_RTIME(ltime, rtime) * (i == I_KEY_PING) +
            // NOTE: CUIDADO COM ESTE LAG AQUI, POIS TALVEZ NAO FOI DESCOBERTO O REAL
            // NOTE: O KEEPER INICIA O PATH->RTT COM UM PATH->RTT_INITIAL
            LTIME_DIFF_RTIME(now, rtime + atomic_get(&path->rtt)/2)
        ) / ((tdiff != 0) + (i == I_KEY_PING) + 1);

        ASSERT(tdiff >= TDIFF_MIN);
        ASSERT(tdiff <= TDIFF_MAX);

        //
        __atomic_store_n(&path->tdiff, tdiff, __ATOMIC_SEQ_CST);

        //
        ping_receive(node, ping);

        if (i == I_KEY_PONG) {
            // CONNECTING -> ESTABLISHED
            __atomic_store_n(&path->answered, now, __ATOMIC_SEQ_CST);
            return PSTATS_I_PONG_GOOD;
        }
    }

    u64 answered = __atomic_load_n(&path->answered, __ATOMIC_SEQ_CST);

    if (answered >= PTIME_MIN) {
        // IF I AM A CLIENT, I ALREADY RECEIVED A PONG
        // IF I AM A SERVER, I ALREADY RECEIVED A SYN AND A SYN-ACK

        // USE THE KNOWN PATH
        skel = &path->skel;

    } elif (answered == ANSWERED_LISTENING) {

        if (i == I_KEY_SYN) {
            // LEARN O PATH NA STACK
            skel = &temp_skel;
        } else { // SYN-ACK
            if (!__atomic_compare_exchange_n(&path->answered, &answered, ANSWERED_ACCEPTING, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
                // COULD NOT LOCK THE PATH
                return PSTATS_I_SYN_ACK_RACED;
            // LEARN O PATH NO PATH
            skel = &path->skel;
        }

        in_discover(path, skb, skel);

        if (skel == &path->skel)
            // UNLOCK PATH
            __atomic_store_n(&path->answered, now, __ATOMIC_SEQ_CST);

    } else
        // STILL ACCEPTING
        return PSTATS_I_SYN_ACK_RACED;

    // RESPONDE COM UM PONG
    ping_send(node, path, skel, now, RTIME(now, tdiff), O_KEY_PONG);

    return PSTATS_I_PING_GOOD;
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

    // AGORA SABE ONDE COMECA O PKT
    pkt_s* const pkt = (ptr + sizeof(hdr_x_s)) - sizeof(pkt_s);

    if (PKT_DATA(pkt) > end)
        // MISSING HEADER + ALIGN
        ret_dev(DSTATS_I_INCOMPLETE);

    const uint nid    = BE16 (pkt->x.src);
    const uint dst    = BE16 (pkt->x.dst);
    const uint pid    = BE8  (pkt->x.path);
    const uint i      = BE8  (pkt->x.version);
    const uint size   = BE16 (pkt->x.dsize);
    const u64  ltime  = BE64 (pkt->x.time);
    const u64  hash   = BE64 (pkt->x.hash);

    if (nid == nodeSelf)
        ret_dev(DSTATS_I_FROM_SELF);

    if (dst != nodeSelf)
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

    path_s* const path = &node->paths[pid];

    if (!(__atomic_load_n(&node->ipaths, __ATOMIC_SEQ_CST) & IPATH(pid)))
        ret_path(PSTATS_I_DISABLED);

    if (i < I_KEYS_DYNAMIC) {
        if (size < XGW_PAYLOAD_MIN)
            // BAD SIZE FOR A NORMAL PACKET
            ret_path(PSTATS_I_SIZE_SMALL);
    } elif (size != PING_SIZE)
            // BAD SIZE FOR A PING PACKET
            ret_path(PSTATS_I_SIZE_NOT_PING);

    if ((PKT_DATA(pkt) + size) > end)
            // WE DON'T HAVE THE ENTIRE PACKET
            ret_path(PSTATS_I_SIZE_TRUNCATED);

    // SITUATION VS PACKET TYPE
    switch (atomic_get(&path->answered)) {

        default: // >= PTIME_MIN
            if (i == I_KEY_SYN)
                // ESTABLISHED RECEBE TUDO MENOS SYN
                ret_path(PSTATS_I_ESTABLISHED_REFUSE_SYN);
            break;

        case ANSWERED_CONNECTING:
            if (i != I_KEY_PONG)
                // CONNECTING SO RECEBE PONGS
                ret_path(PSTATS_I_CONNECTING_REQUIRE_PONG);
            break;

        case ANSWERED_LISTENING:
            if (i == I_KEY_SYN) {
                if (0)
                    // LIMITAR A QUANTIDADE DE SYNS RECEBIVEIS A CADA KEEPER INTERVAL
                    ret_path(PSTATS_I_LISTENING_SYN_TOO_MANY);
                if (ltime != atomic_get(&path->syn))
                    // ELE NAO CONHECE NOSSO CODIGO
                    ret_path(PSTATS_I_LISTENING_SYN_WRONG);
            } elif (i != I_KEY_PING)
                    // LISTENING SO RECEBE SYN E PING
                    ret_path(PSTATS_I_LISTENING_REFUSE_DATA_AND_PONG);
            break;

        case ANSWERED_ACCEPTING:
            // LISTENING, MAS EM ESTADO DE ACCEPTING
            ret_path(PSTATS_I_ACCEPTING);
            break;
    }

    if (i != I_KEY_SYN)
        // NOTE: CONSIDERA QUE O PEER ESTIMOU NOSSO TIME A PARTIR DO RTT CALCULADO POR ELE, QUE PODE SER ATE RTT_MAX (E QUE ESTES SAO DIFERENTES DOS NOSSOS)
        // NOTE: CONSIDERA CLOCK SKELS LOCAL/REMOTE
        // NOTE: CONSIDERA QUE LEVOU UM LATENCY ATÉ CHEGAR AQUI
        // NOTE: CONSIDERA CPU BUSY TIMES
        if (ABS_DIFF(ltime + atomic_get(&path->rtt)/2, path->mask + get_current_ms()) > atomic_get(&path->rtt_var)/2)
            // ELE NAO CONHECE NOSSO TIME (OU TEM UM SKEW GRANDE)
            ret_path(PSTATS_I_LTIME_MISMATCH);

    // DECRYPT
    if (pkt_decrypt(node, i, pkt, size) != hash)
        // CORRUPT
        ret_path(PSTATS_I_HASH_MISMATCH);

    // IS A EXPECTED TYPE FOR OUR STATUS
    // IS AUTHENTIC (hash)
    // IS SYNCED (time)

    if (i >= I_KEY_PING)
        ret_path(in_ping(node, skb, pkt));

    // NORMAL PACKET

    // AVANCA O ALIGNMENT
    void* const orig = PKT_DATA(pkt);

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

_ret_path: _stat = path->stats;       goto _ret;
_not_xgw:   stat = DSTATS_I_NOT_XGW; // JUST SOME PACKET, TRAVELING AROUND THE WORLD IN 80 HOPS
_ret_dev:  _stat = dstats;            goto _ret;
_ret_node: _stat = nstats[nid];
_ret:

    stat_inc_count(&_stat[stat].count);
    stat_inc_bytes(&_stat[stat].bytes, skb->len);

    // NOTE QUE TODOS OS STATS PASS SAO 0
    return stat;
}
