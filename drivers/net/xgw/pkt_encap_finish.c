
static inline void pkt_encap_finish (pkt_s* const pkt, const uint size) {

    const enum H_TYPE type = pkt->type;

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
