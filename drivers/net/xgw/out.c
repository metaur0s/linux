
static netdev_tx_t out (skb_s* const skb, net_device_s* const dev) {

    // NOTE: THIS SIZE MAY BE WRONG, AS WE DIDNT LINEARIZE IT YET
    uint stat; volatile stat_s* _stat;

    if (skb_is_nonlinear(skb))
        ret_dev(DSTATS_O_DATA_NON_LINEAR);

    const size_t size = skb->len;

    if (size < XGW_PAYLOAD_MIN)
        ret_dev(DSTATS_O_DATA_SIZE_SMALL);

    if (size > XGW_PAYLOAD_MAX)
        ret_dev(DSTATS_O_DATA_SIZE_BIG);

#ifdef CONFIG_XGW_GATEWAY_TCP_PROXY
    switch (skb->mark & 0xFFFF0000U) { // TODO: TEM QUE IMPEDIR DE SETAR MANUALMENTE ESTES MARKS NO SETSOCKOPT, IPTABLES ETC

        case XGW_TCP_PROXY_MARK_4: {

            ASSERT(skb->protocol == BE16(ETH_P_IP));

            ip4_s* const ip = SKB_NETWORK(skb);

            ASSERT(ip->proto == BE8(IPPROTO_TCP));

            // TODO: SE FOR SYN/SYN-ACK, ADJUST MSS
            ip->sport  = BE16(skb->mark & 0xFFFFU);

        } break;

        case XGW_TCP_PROXY_MARK_6: {

            // TODO:
            ASSERT(skb->protocol == BE16(ETH_P_IPV6));

            ip6_s* const ip = SKB_NETWORK(skb);

            ASSERT(ip->proto == BE8(IPPROTO_TCP));

            // TODO: SE FOR SYN/SYN-ACK, ADJUST MSS
            ip->sport  = BE16(skb->mark & 0xFFFFU);

        } break;
    }
#endif

    // THE PAYLOAD (THIS WILL POINT TO THE NETWORK HEADER)
    u64* const p = SKB_NETWORK(skb);

    // WILL GET DESTINATION NODE AND HASH THE PATH
    u64 nid, cid;

    // NOTE: ASSUMINDO QUE O SKB->LEN TEM AO MENOS ESTES CABECALHOS
    // NOTE: ASSUMINDO QUE NAO TEM IPV4/IPV6 OPTIONS
    // NOTE: SE ATRAPALHA COM ICMP
    if ((cid = BE64(p[0]) >> 56) == 0x45) { ASSERT(skb->protocol == BE16(ETH_P_IP));
        // IPV4 (NOTE: ASSUMING NO IP OPTION/FRAGMENTATION)
        // PROTO, SADDR, DADDR SPORT DPORT
        cid = (p[1] & BE64(0x00FF0000FFFFFFFFULL)) + p[2];
        // DEIXA SO O PREFIXO E O NODE
        // THIS 32 IS BECAUSE WE HAVE ALSO READ THE PORTS
        nid = ((BE64(p[2]) >> 32) ^ V4_PREFIX) >> (32 - V4_WIDTH_PREFIX - V4_WIDTH_NODE);
        // OS BITS DA REDE QUE DIFERIREM DARAO 1, FAZENDO COM QUE O HID SEJA GRANDE
        // OS BITS DO NODE DARAO OS MESMOS
    } elif ((cid >> 4) == 0x6) { ASSERT(skb->protocol == BE16(ETH_P_IPV6));
        // IPV6 (NOTE: ASSUMING NO IP NEXT HEADER/FRAGMENTATION)
        // FLOW, PROTO, SADDR, DADDR
        cid = (p[0] & BE64(0x000FFFFF0000FF00ULL)) + p[1] + p[2] + p[3] + p[4];
        nid = (BE64(p[3]) ^ V6_PREFIX) >> (64 - V6_WIDTH_PREFIX - V6_WIDTH_NODE);
    } else
        // UNSUPORTED
        ret_dev(DSTATS_O_DATA_UNKNOWN);

    // TODO: CRIAR O XGW COMNETDEV priv?
    if (dev == xgw) {
        // IF ITS THROUGHT THE GLOBAL INTERFACE, WE MUST IDENTIFY THE DESTINATION NODE BY THE DESTINATION ADDRESS
        if (nid >= NODES_N) {
            // DESTINATION IS NOT A NODE
            // NODE IS ONE OF THE GATEWAYS
            if (gwsN == 0)
                ret_dev(DSTATS_O_DATA_NO_GW);
            nid = gws[popcount(cid) % gwsN];
        }
    } else
        // WHATEVER THE DESTINATION IS, IT IS TUNNELED TO A SPECIFIC NODE BY IT'S INTERFACE
        // TODO: UM FILTRO EM OUTRAS COISAS PARA NAO DEIXAR PASSAR PARA ENDERECOS XGW EM OUTRAS INTERFACES
        // TODO: UM FILTRO EM OUTRAS COISAS PARA NAO DEIXAR PASSAR PARA MARCAS XGW EM OUTRAS INTERFACES
        // IN THIS CASE THE NID READEN FROM THE ADDRESSES IS USELESS; AS WE CAN ROUTE TO A NODE THROUGHT ANODER ONE
        nid = *(uint*)netdev_priv(dev); // TODO: JUMTO COM AQUELE IFFLAGS??

    ASSERT(nid < NODES_N);

    //
#ifdef CONFIG_XGW_NMAP
    nid = nmap[nid];
#endif

    ASSERT(nid < NODES_N);

    if (nid == nodeSelf)
        // CANNOT SEND TO ITSELF
        ret_dev(DSTATS_O_DATA_TO_SELF);

    // TODO: CONTINUAR RECEBENDO PACOTES DE CONTROLE/PING/PONG MESMO COM A INTERFACE DESATIVADA
    //        DAI SERA INTERESSANTE UMA FLAG GLOBAL XGW ON / OFF, NO MESMO ESQUEMA QUE O NODE->ON & PATH->ON

    // IDENTIFIED THE NODE
    // TODO: IF THE NODE IS NOT AVAILABLE, SEND IT TO ANOTHER ONE
    //     -- WILL NEED TO REPORT THE NODES WE CAN REACH IN THE PING, WITH A BIT MAP: 1024*8 = 8192 NODES
    //     -- WILL NEED SOME KIND OF TTL -> junto com o xPath, o xTTL
    //            e ai se o xttl for != 0, intepreta, desconta um, e manda ele (nao vai poder desencriptar)
    node_s* const node = nodes_get_unlocked(nid);

    if (node == NULL)
        ret_node(NSTATS_O_DATA_INEXIST);

    if (node_is_off(node))
        ret_node(NSTATS_O_DATA_DISABLED);

    if (node->mtu < size)
        ret_node(NSTATS_O_DATA_MTU_EXCEEDED);

    const u64 opaths = atomic_get(&node->opaths);

    if (!opaths)
        ret_node(NSTATS_O_DATA_NO_PATH);

    // CHOOSE CONN
    cid += cid >> 32;
    cid += cid >> 16;
    cid %= node->connsN;

    u64* const conn = &node->conns[cid];

    const u64 _now = get_current_ms();

    ASSERT(_now >= RTIME_MIN);
    ASSERT(_now <= RTIME_MAX);

    // LOAD STREAM TIMEOUT + PID
    const u64 burst = atomic_get(conn);

    // CHOOSE A PATH
    // STARTING FROM CURRENT, BUT CHANGE IF IDLE
    const uint pid0 = (burst + ((burst >> 5) < _now)) % PATHS_N;
    // NOTE: NO CASO DE OPATHS SER 0, ESTE VALOR FINAL SERIA UNSPECIFIED
    // NOTE: O ULTIMO GRUPO TEM QUE SER REPETIDO
    const uint pid = __ctz((opaths >> pid0) << pid0) % PATHS_N;

    ASSERT(opaths & OPATH(pid));

    path_s* const path = &node->paths[pid];

    // STORE STREAM TIMEOUT + PID
    // CONSIDERAR O TEMPO DE IDA + CPU BUSY TIME + IMPRECISOES
    atomic_set(conn, ((_now + (atomic_get(&path->rtt) * 3) / 4) << 5) | pid); // olatency

#if 1
    if (skb->ip_summed == CHECKSUM_PARTIAL)
        if (skb_checksum_help(skb))
            ret_path(PSTATS_O_DATA_CKSUM_FAILED);
#endif

    // NOTE: THIS STAT WILL ONLY HAPPEN ON DATA, NOT ON PING/PONG
    if ((PTR(p) - (path->skel.hsize + PKT_ALIGN_SIZE)) < SKB_HEAD(skb))
        ret_path(PSTATS_O_DATA_NO_HEADROOM);

    pkt_encapsulate(node, atomic_get(&node->oIndex), RTIME(path->mask + _now, atomic_get(&path->tdiff)), &path->skel, skb, p, size);

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    dev_queue_xmit(skb);
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED

    stat = PSTATS_O_DATA_OK;

_ret_path: _stat = path->stats; goto _ret;
_ret_node: _stat = nstats[nid]; goto _ret;
_ret_dev:  _stat = dstats;
_ret:

    stat_inc_count(&_stat[stat].count);
    stat_inc_bytes(&_stat[stat].bytes, skb->len);

    if (stat != PSTATS_O_DATA_OK)
        dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}
