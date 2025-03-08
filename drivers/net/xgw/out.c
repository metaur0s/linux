
// NOTE: ASSUME NO IPV4 OPTIONS
// ip: IP PACKET
// size: IP SIZE
static inline u16 tcp_checksum4 (const void* ip, uint size) {

    ASSERT(size >= offsetof(ip4_s, sport));

    uint sum = IPPROTO_TCP + size - IP4_SIZE;

    size -= offsetof(ip4_s, saddr);
    ip   += offsetof(ip4_s, saddr);

    do {
        sum += BE16(*(u16*)ip);
                           ip += sizeof(u16);
    } while ((size -= sizeof(u16))
                   >= sizeof(u16));

    if (size)
        sum += *(u8*)ip << 8;

    sum +=  sum >> 16;
    sum  = ~sum;
    sum &= 0xFFFFU;

    return sum;
}

// NOTE: ASSUME NO IPV6 OPTIONS
static inline u16 tcp_checksum6 (const void* ip, uint size) {

    ASSERT(size >= (IP6_SIZE + TCP_SIZE));
    ASSERT((ip + IP6_SIZE) == &((ip6_s*)ip)->sport);

    uint sum = IPPROTO_TCP + size - IP6_SIZE;

    size -= offsetof(ip6_s, saddr);
    ip   += offsetof(ip6_s, saddr);

    do {
        sum += BE16(*(u16*)ip);
                           ip += sizeof(u16);
    } while ((size -= sizeof(u16))
                   >= sizeof(u16));

    if (size)
        sum += *(u8*)ip << 8;

    sum +=  sum >> 16;
    sum  = ~sum;
    sum &= 0xFFFFU;

    return sum;
}

// TODO:
static inline u16 udp_checksum6 (const void* ip, uint size) {

    return 0;
}

// MUST BE SMALL AND FAST
// TODO: AQUI ENCRIPTA E NAO RETORNA NADA xD
// TODO: SE ESSA PORRA COMPUTAR CHECKSUM TCP/UDP,
// ENTAO VAI TER QUE SER DEPOIS DE ENCRYPTAR
static void pkt_encapsulate (const node_s* const node, const uint o, const u64 rtime, const pkt_s* const skel, skb_s* const skb, void* const restrict orig, const uint size) {

    ASSERT(size >= XGW_PAYLOAD_MIN);
    ASSERT(size <= XGW_PAYLOAD_MAX);

    pkt_s* const pkt = orig - (PKT_SIZE + PKT_ALIGN_SIZE);

    ASSERT(skel->x.src  == BE16(nodeSelf));
    ASSERT(skel->x.dst  == BE16(node->nid));
 // ASSERT(skel->x.path == BE8(path->pid));

    ASSERT(skel->phys);

    ASSERT((skel->moffset + skel->msize) == skel->noffset);
    ASSERT((skel->moffset + skel->hsize) == sizeof(pkt_s));

    ASSERT(skel->moffset >= 0);
    ASSERT(skel->noffset >= skel->moffset);
    ASSERT(skel->Noffset >= skel->noffset);
    ASSERT(skel->toffset >= skel->Noffset);
    ASSERT(skel->toffset <= offsetof(pkt_s, x));

    // INSERT OUR HEADER
    memcpy(PTR(pkt) + skel->moffset, PTR(skel) + skel->moffset, skel->hsize);

    skb->len       = pkt->hsize + PKT_ALIGN_SIZE + size; // TODO: COLOCAR ESSE U64 NOS HSIZES DOS MODELS, E RETIRAR DAQUI
    skb->dev       = pkt->phys;
    skb->mac_len   = pkt->msize;
    skb->protocol  = pkt->protocol;
    // NOTE: ISSO AQUI NO PING/PONG
 // skb->ip_summed = CHECKSUM_NONE;

    // NOTE: pkt->[mnt]offset NUNCA PODE COMECAR EM 0 POIS O COMECINHO É O RESERVADO
    skb->data = PTR(pkt) + pkt->moffset;

    // skb_set_mac_header / skb_reset_mac_header
    // skb_set_network_header / skb_reset_network_header
    // SE NAO FOR TER MAC HEADER, ENTAO ESTEMAC_HEADER TEM QUE TERINAR APONTANDO PRO MESMO QUE O DATA
    // OU SEJA, BASTA QUE O PKT->MOFFSET SEJA IGAL AO QUE APONTA PRO INICIO DO ENCAPSULAMENTO
    // NOTE: WE NEED TO SET TAIL ALSO, BECAUSE WE ARE ALSO CREATING PACKETS FOR PING/PONG
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header       = (PTR(pkt) + pkt->moffset) - SKB_HEAD(skb);
    skb->network_header   = (PTR(pkt) + pkt->noffset) - SKB_HEAD(skb);
    skb->transport_header = (PTR(pkt) + pkt->toffset) - SKB_HEAD(skb);
    skb->tail             = (PTR(pkt) + PKT_SIZE + PKT_ALIGN_SIZE + size) - SKB_HEAD(skb);
#else
    skb->mac_header       =  PTR(pkt) + pkt->moffset;
    skb->network_header   =  PTR(pkt) + pkt->noffset; // TODO: TEM QUE SER O VLAN???
    skb->transport_header =  PTR(pkt) + pkt->toffset;
    skb->tail             = (PTR(pkt) + PKT_SIZE + PKT_ALIGN_SIZE + size);
#endif

    ASSERT(SKB_DATA(skb) >= SKB_HEAD(skb));
    ASSERT(SKB_DATA(skb) <  SKB_TAIL(skb));

    ASSERT(SKB_HEAD(skb) <= PTR(pkt));
    ASSERT(SKB_DATA(skb) >= PTR(pkt)); // O DATA É UM DESTES: MAC/NETWORK/TRANSPORT/&PKT->X

    ASSERT((SKB_TAIL(skb) - SKB_DATA(skb)) == skb->len);

    ASSERT(SKB_MAC      (skb) == (PTR(pkt) + pkt->moffset));
    ASSERT(SKB_NETWORK  (skb) == (PTR(pkt) + pkt->noffset));
    ASSERT(SKB_TRANSPORT(skb) == (PTR(pkt) + pkt->toffset));

    const enum H_TYPE type = pkt->type;

    //
    random64_n(pkt->p, PKT_ALIGN_RANDOMS, SUFFIX_ULL(CONFIG_XGW_RANDOM_ENCRYPT_ALIGN));

    //
    pkt->x.dsize   = BE16(size);
    pkt->x.version = BE8(node->oVersions[o]);
    pkt->x.time    = BE64(rtime);
    pkt->x.hash    = BE64(pkt_encrypt(node, o, pkt, size));

    switch (type) {

        case H_TYPE_ETH_PPP_IP4:
        case H_TYPE_ETH_VLAN_PPP_IP4:

            pkt->encap_eth_ppp_ip4.ppp.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + size + sizeof(hdr_ip4_s) + sizeof(u16));

            fallthrough;
        case H_TYPE_IP4:
        case H_TYPE_ETH_IP4:
        case H_TYPE_ETH_VLAN_IP4:

     ASSERT(pkt->encap_eth_ppp_ip4.ip4.cksum == BE16(0));
            pkt->encap_eth_ppp_ip4.ip4.size  = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + size + sizeof(hdr_ip4_s));
            pkt->encap_eth_ppp_ip4.ip4.cksum = ip_fast_csum(&pkt->encap_ip4.ip4, 5);

            break;

        case H_TYPE_ETH_PPP_IP6:
        case H_TYPE_ETH_VLAN_PPP_IP6:

            pkt->encap_eth_ppp_ip6.ppp.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + size + sizeof(hdr_ip6_s) + sizeof(u16));

            fallthrough;
        case H_TYPE_IP6:
        case H_TYPE_ETH_IP6:
        case H_TYPE_ETH_VLAN_IP6:

            pkt->encap_eth_ppp_ip6.ip6.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + size);

            break;

        case H_TYPE_IP4_UDP:
        case H_TYPE_ETH_IP4_UDP:
        case H_TYPE_ETH_VLAN_IP4_UDP:

            ASSERT(pkt->encap_ip4_udp.udp.cksum == BE16(0));
            ASSERT(pkt->encap_ip4_udp.ip4.cksum == BE16(0));

            pkt->encap_ip4_udp.udp.size  = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + size + sizeof(hdr_udp_s));
            pkt->encap_ip4_udp.ip4.size  = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + size + sizeof(hdr_udp_s) + sizeof(hdr_ip4_s));
            pkt->encap_ip4_udp.ip4.cksum = ip_fast_csum(&pkt->encap_ip4_udp.ip4, 5);

            break;

        case H_TYPE_IP6_UDP:
        case H_TYPE_ETH_IP6_UDP: // TODO: O IPV6 OBRIGA UDP CHECKSUM. ESTA DEIXANDO O ZERO AQUI, MAS DEVERA COMPUTAR DEPOIS
        case H_TYPE_ETH_VLAN_IP6_UDP:

            ASSERT(pkt->encap_ip6_udp.udp.cksum == BE16(0));

            pkt->encap_ip6_udp.udp.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + size + sizeof(hdr_udp_s));
            pkt->encap_ip6_udp.ip6.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + size + sizeof(hdr_udp_s));

            break;

        case H_TYPE_ETH_PPP:
        case H_TYPE_ETH_VLAN_PPP:

            pkt->encap_eth_ppp.ppp.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + size + 2);

            break;

        case H_TYPE_IP4_TCP:
        case H_TYPE_ETH_IP4_TCP:
        case H_TYPE_ETH_VLAN_IP4_TCP:

            break;

        case H_TYPE_IP6_TCP:
        case H_TYPE_ETH_IP6_TCP:
        case H_TYPE_ETH_VLAN_IP6_TCP:

            break;

        case H_TYPE_RAW:
        case H_TYPE_ETH:
        case H_TYPE_ETH_VLAN:
            //
            break;
    }
}

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

    // CANNOT SEND TO ITSELF
    if (nid == nodeSelf)
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

    const path_s* path; u64 to, now; uint pid;

    // CHOOSE CONN
    u64* const conn = &node->conns[(cid + (cid >> 16) + (cid >> 32) + (cid >> 48)) % node->connsN];

    // NEED THIS ATOMICITY LOOP BECAUSE SOMEONE ELSE USE THE CURRENT (OR OTHER ONE) AND OVERWRITE WHAT WE JUST SET
    do {
        // LOAD STREAM TIMEOUT + PID
        to = __atomic_load_n(conn, __ATOMIC_SEQ_CST);

        // NOTE: ESTE TIME PODE FICAR COMPROMETIDO NO CASO DE INTERRUPTS E/OU PREEMPTION
        now = get_jiffies_64() * PATHS_N;

        // CHOOSE A PATH - STARTING FROM CURRENT, CHANGED IF IDLE
        // NOTE: O ULTIMO GRUPO TEM QUE SER REPETIDO
        pid = (to + (to < now)) % PATHS_N;
        // NOTE: NO CASO DE OPATHS SER 0, ESTE VALOR FINAL SERA UNSPECIFIED
        pid = __ctz((opaths >> pid) << pid) % PATHS_N;

        ASSERT(opaths & OPATH(pid));

        path = &node->paths[pid];

        // STORE STREAM TIMEOUT + PID
        // CONSIDERAR O LATENCY (SÓ DE IDA) + CPU BUSY TIME + IMPRECISOES
        // TODO: + rtt_var
    } while (!__atomic_compare_exchange_n(conn, &to, (now + ((atomic_get(&path->latency) + 16) * PATHS_N)) | pid, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));

#if 1
    if (skb->ip_summed == CHECKSUM_PARTIAL)
        if (skb_checksum_help(skb))
            ret_path(PSTATS_O_DATA_CKSUM_FAILED);
#endif

    // NOTE: THIS STAT WILL ONLY HAPPEN ON DATA, NOT ON PING/PONG
    if ((PTR(p) - (path->skel.hsize + PKT_ALIGN_SIZE)) < SKB_HEAD(skb))
        ret_path(PSTATS_O_DATA_NO_HEADROOM);

    // TODO: USAR O GET JIFFIES ACIMA
    const u64 rtime = get_current_ms() + atomic_get(&path->tdiff);

    const uint o = atomic_get(&node->oUse);

    pkt_encapsulate(node, o, rtime, &path->skel, skb, p, size);

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    dev_queue_xmit(skb);
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED

    stat = PSTATS_O_DATA_OK;
_ret_path:
           _stat = node->pstats[pid]; goto _ret;
_ret_node: _stat = nstats[nid];       goto _ret;
_ret_dev:  _stat = dstats;
_ret:

    atomic_inc(&_stat[stat].count);
    atomic_add(&_stat[stat].bytes, skb->len);

    if (stat != PSTATS_O_DATA_OK)
        dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}
