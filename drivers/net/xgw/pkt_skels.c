
// TODO: NO CASO DO IP4 (RAW) O TRANSPORTE É O PROPRIO XHEADER

// IFRAG BE16 (0b0100000000000000U)

#define SKEL_IP6_FLOW(node, path) (((node)->nid * PATHS_N) + ((path) - (node)->paths))

static const pkt_s models [H_TYPES_N] = {

    [H_TYPE_ETH] = {
        .type     = H_TYPE_ETH,
        .hsize    = H_SIZE_ETH,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_s, eth),
        .noffset  = offsetof(pkt_s, x),
        .Noffset  = offsetof(pkt_s, x),
        .toffset  = offsetof(pkt_s, x),
        .protocol = BE16(ETH_P_XGW),
        .encap_eth = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_XGW),
            },
        }
    },

    [H_TYPE_ETH_PPP] = {
        .type     = H_TYPE_ETH_PPP,
        .hsize    = H_SIZE_ETH_PPP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ppp_s, eth),
        .noffset  = offsetof(encap_eth_ppp_s, ppp),
        .Noffset  = offsetof(encap_eth_ppp_s, ppp),
        .toffset  = offsetof(encap_eth_ppp_s, ppp),
       ._reserved = offsetof(encap_eth_ppp_s, ppp),
        .protocol = BE16(ETH_P_PPP_SES),
        .encap_eth_ppp = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_PPP_SES), // 0x8864
            },
            .ppp = {
                .code    = BE16(0x1100), // VERSION (0x1) | TYPE (0x1) | CODE (0x00)
                .session = BE16(0),
                .size    = BE16(0), // IP SIZE + 2
                .proto   = BE16(ETH_P_XGW),
            },
        }
    },

    [H_TYPE_ETH_IP4] = {
        .type     = H_TYPE_ETH_IP4,
        .hsize    = H_SIZE_ETH_IP4,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ip4_s, eth),
        .noffset  = offsetof(encap_eth_ip4_s, ip4),
        .Noffset  = offsetof(encap_eth_ip4_s, ip4),
        .toffset  = offsetof(pkt_s, x),
        .protocol = BE16(ETH_P_IP),
        .encap_eth_ip4 = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_IP),
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            }
        }
    },

    [H_TYPE_ETH_PPP_IP4] = {
        .type     = H_TYPE_ETH_PPP_IP4,
        .hsize    = H_SIZE_ETH_PPP_IP4,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ppp_ip4_s, eth),
        .noffset  = offsetof(encap_eth_ppp_ip4_s, ppp),
        .Noffset  = offsetof(encap_eth_ppp_ip4_s, ip4),
        .toffset  = offsetof(pkt_s, x),
       ._reserved = offsetof(encap_eth_ppp_ip4_s, ppp),
        .protocol = BE16(ETH_P_PPP_SES),
        .encap_eth_ppp_ip4 = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(0x0021), // ETH_P_IP
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            }
        }
    },

    [H_TYPE_ETH_PPP_IP6] = {
        .type     = H_TYPE_ETH_PPP_IP6,
        .hsize    = H_SIZE_ETH_PPP_IP6,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ppp_ip6_s, eth),
        .noffset  = offsetof(encap_eth_ppp_ip6_s, ip6),
        .Noffset  = offsetof(encap_eth_ppp_ip6_s, ip6),
        .toffset  = offsetof(pkt_s, x),
       ._reserved = offsetof(encap_eth_ppp_ip6_s, ppp),
        .protocol = BE16(ETH_P_PPP_SES),
        .encap_eth_ppp_ip6 = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(0x0057), // ETH_P_IPV6
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_XGW),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            }
        }
    },

    [H_TYPE_ETH_IP6] = {
        .type     = H_TYPE_ETH_IP6,
        .hsize    = H_SIZE_ETH_IP6,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ip6_s, eth),
        .noffset  = offsetof(encap_eth_ip6_s, ip6),
        .Noffset  = offsetof(encap_eth_ip6_s, ip6),
        .toffset  = offsetof(encap_eth_ip6_s, ip6),
        .protocol = BE16(ETH_P_IPV6),
        .encap_eth_ip6 = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_IPV6),
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_XGW),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            }
        }
    },

    [H_TYPE_ETH_IP4_UDP] = {
        .type     = H_TYPE_ETH_IP4_UDP,
        .hsize    = H_SIZE_ETH_IP4_UDP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ip4_udp_s, eth),
        .noffset  = offsetof(encap_eth_ip4_udp_s, ip4),
        .Noffset  = offsetof(encap_eth_ip4_udp_s, ip4),
        .toffset  = offsetof(encap_eth_ip4_udp_s, udp),
        .protocol = BE16(ETH_P_IP),
        .encap_eth_ip4_udp = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_IP),
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_UDP),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_ETH_IP6_UDP] = {
        .type     = H_TYPE_ETH_IP6_UDP,
        .hsize    = H_SIZE_ETH_IP6_UDP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ip6_udp_s, eth),
        .noffset  = offsetof(encap_eth_ip6_udp_s, ip6),
        .Noffset  = offsetof(encap_eth_ip6_udp_s, ip6),
        .toffset  = offsetof(encap_eth_ip6_udp_s, udp),
        .protocol = BE16(ETH_P_IPV6),
        .encap_eth_ip6_udp = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_IPV6),
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_UDP),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_IP4_UDP] = {
        .type     = H_TYPE_IP4_UDP,
        .hsize    = H_SIZE_IP4_UDP,
        .msize    = 0,
        .moffset  = offsetof(encap_ip4_udp_s, ip4), // TODO: TEM QUE TER ISSO?
        .noffset  = offsetof(encap_ip4_udp_s, ip4),
        .Noffset  = offsetof(encap_ip4_udp_s, ip4),
        .toffset  = offsetof(encap_ip4_udp_s, udp),
        .protocol = BE16(ETH_P_IP),
        .encap_ip4_udp = {
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_UDP),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_IP6_UDP] = {
        .type     = H_TYPE_IP6_UDP,
        .hsize    = H_SIZE_IP6_UDP,
        .msize    = 0,
        .moffset  = offsetof(encap_ip6_udp_s, ip6), // TODO: TEM QUE TER ISSO?
        .noffset  = offsetof(encap_ip6_udp_s, ip6),
        .Noffset  = offsetof(encap_ip6_udp_s, ip6),
        .toffset  = offsetof(encap_ip6_udp_s, udp),
        .protocol = BE16(ETH_P_IPV6),
        .encap_ip6_udp = {
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_UDP),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_IP4] = {
        .type     = H_TYPE_IP4,
        .hsize    = H_SIZE_IP4,
        .msize    = 0,
        .moffset  = offsetof(encap_eth_ip4_s, ip4),
        .noffset  = offsetof(encap_eth_ip4_s, ip4),
        .Noffset  = offsetof(encap_eth_ip4_s, ip4),
        .toffset  = offsetof(pkt_s, x),
        .protocol = BE16(ETH_P_IP),
        .encap_ip4 = {
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            }
        }
       //encap->i4.ip4.cksum  = ip_fast_csum(&encap->i4.ip4, 5),
    },

#if 0
    [H_TYPE_IP6] = {

    },

#endif

    // TODO: NO CASO DO VLAN, O TRANSPORTE APONTA PARA O VLAN OU PARA O IP?
    [H_TYPE_ETH_VLAN_IP4] = {
        .type     = H_TYPE_ETH_VLAN_IP4,
        .hsize    = H_SIZE_ETH_VLAN_IP4,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ip4_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ip4_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ip4_s, ip4),
        .toffset  = offsetof(encap_eth_vlan_ip4_s, ip4),
        .protocol = BE16(0),
        .encap_eth_vlan_ip4 = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id = BE16(0),
                .proto = BE16(ETH_P_IP),
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
        }
    },

    [H_TYPE_ETH_VLAN_PPP] = {
        .type     = H_TYPE_ETH_VLAN_PPP,
        .hsize    = H_SIZE_ETH_VLAN_PPP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ppp_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ppp_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ppp_s, ppp),
        .toffset  = offsetof(encap_eth_vlan_ppp_s, ppp),
       ._reserved = offsetof(encap_eth_vlan_ppp_s, ppp),
        .protocol = BE16(0),
        .encap_eth_vlan_ppp = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id    = BE16(0),
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(ETH_P_XGW),
            },
        }
    },

    [H_TYPE_ETH_VLAN_PPP_IP4] = {
        .type     = H_TYPE_ETH_VLAN_PPP_IP4,
        .hsize    = H_SIZE_ETH_VLAN_PPP_IP4,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ppp_ip4_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ppp_ip4_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ppp_ip4_s, ip4),
        .toffset  = offsetof(encap_eth_vlan_ppp_ip4_s, ip4),
       ._reserved = offsetof(encap_eth_vlan_ppp_ip4_s, ppp),
        .protocol = BE16(0),
        .encap_eth_vlan_ppp_ip4 = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id    = BE16(0),
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(0x0021), // ETH_P_IP
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
        }
    },

    [H_TYPE_ETH_VLAN_PPP_IP6] = {
        .type     = H_TYPE_ETH_VLAN_PPP_IP6,
        .hsize    = H_SIZE_ETH_VLAN_PPP_IP6,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ppp_ip6_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ppp_ip6_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ppp_ip6_s, ip6),
        .toffset  = offsetof(encap_eth_vlan_ppp_ip6_s, ip6),
       ._reserved = offsetof(encap_eth_vlan_ppp_ip6_s, ppp),
        .protocol = BE16(0),
        .encap_eth_vlan_ppp_ip6 = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id    = BE16(0),
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(0x0057), // ETH_P_IPV6
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_XGW),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
        }
    },

    [H_TYPE_ETH_VLAN_IP6] = {
        .type     = H_TYPE_ETH_VLAN_IP6,
        .hsize    = H_SIZE_ETH_VLAN_IP6,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ip6_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ip6_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ip6_s, ip6),
        .toffset  = offsetof(encap_eth_vlan_ip6_s, ip6),
        .protocol = BE16(0),
        .encap_eth_vlan_ip6 = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id = BE16(0),
                .proto = BE16(ETH_P_IPV6),
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_XGW),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
        }
    },

    [H_TYPE_ETH_VLAN] = {
        .type     = H_TYPE_ETH_VLAN,
        .hsize    = H_SIZE_ETH_VLAN,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_s, eth),
        .noffset  = offsetof(encap_eth_vlan_s, vlan), // TODO: PRECISA DISSO?
        .Noffset  = offsetof(encap_eth_vlan_s, vlan),
        .toffset  = offsetof(encap_eth_vlan_s, vlan),
        .protocol = BE16(0), // ETH_P_8021Q / ETH_P_8021AD
        .encap_eth_vlan = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id    = BE16(0),
                .proto = BE16(ETH_P_XGW),
            },
        }
    },

    [H_TYPE_ETH_VLAN_IP4_UDP] = {
        .type     = H_TYPE_ETH_VLAN_IP4_UDP,
        .hsize    = H_SIZE_ETH_VLAN_IP4_UDP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ip4_udp_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ip4_udp_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ip4_udp_s, ip4),
        .toffset  = offsetof(encap_eth_vlan_ip4_udp_s, udp),
        .protocol = BE16(0),
        .encap_eth_vlan_ip4_udp = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id = BE16(0),
                .proto = BE16(ETH_P_IP),
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_UDP),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_ETH_VLAN_IP6_UDP] = {
        .type     = H_TYPE_ETH_VLAN_IP6_UDP,
        .hsize    = H_SIZE_ETH_VLAN_IP6_UDP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ip6_udp_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ip6_udp_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ip6_udp_s, ip6),
        .toffset  = offsetof(encap_eth_vlan_ip6_udp_s, udp),
        .protocol = BE16(0),
        .encap_eth_vlan_ip6_udp = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id = BE16(0),
                .proto = BE16(ETH_P_IPV6),
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_UDP),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

};
