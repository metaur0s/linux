
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

static inline void in_discover (const path_s* const path, const skb_s* const skb, pkt_s* const skel) {

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
        ip6->flow = BE16(SKEL_IP6_FLOW(path->node, path));
    }
}
