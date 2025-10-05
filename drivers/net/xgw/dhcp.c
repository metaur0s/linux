
#if 0

#define XADDR_MATCH_PHYS       0
#define XADDR_MATCH_IF_IDX     1
#define XADDR_MATCH_ETH_DST    2
#define XADDR_MATCH_ETH_PROTO  3
#define XADDR_MATCH_VLAN_PROTO 4
#define XADDR_MATCH_VLAN_ID    5
#define XADDR_MATCH_IP_PROTO   6
#define XADDR_MATCH_IP_DST     7
#define XADDR_MATCH_TRANSP_DST 8

struct x_addr_s {
    net_device_s* phys;
    u64 ipDst [2];
    union {
        struct {
            u16 ethDst [3];
            u16 ethProto; // IPV4 / IPV6
        };  u64 ethDst_; // FOR FAST ACCESS
    };
    u16 vProto;
    u16 vID;
    u16 ipProto; // UDP / TCP
    u16 transpDst; // TRANSPORT DST
    u16 code; // FOR IDENTIFICATION
    u16 dhcpID; // DHCP ID
    u16 matchesYes; // MATCHES NEEDED
    u16 matchesNot;
};

#define ADDRS_N 127

static uint addrsN;
static x_addr_s xaddrs [ADDRS_N + 1];

// TODO: E QUANTO AO VLAN?
static int testa (dhcp_s* const entry, skb_s* const skb) {

    if (entry->dev == skb->dev) {

        if (entry->neighProtocol == skb->protocol
         && entry->neighSize     == skb->len) { // NOTA: SO SETA ESSE NEIGHPROTOCOL  E NEIGHSIZE QUANDO OBTER O IP VALIDO
            // NEIGH

            if (entry->neighProtocol == BE16(ETH_P_ARP)) {
                // ARP

                if (entry->v4.ip != msg->askedForThisIP)
                    return DHCP_NOT_HANDLED;

        // build response

            } else {
                // RA

                if (memcmp(entry->v6.ip, msg->askedForThisIP, 16))
                    return DHCP_NOT_HANDLED;

        // build response
            }

        if (atomic_inc(limitreached, 1) < 32) {

            // ALLOC SKB
            // NOTE: AQUI ESQUECEMOS O SKB RECEBIDO
            skb_s* const skb = skb_alloc();

            // COPY MSG
            memcpy();

            // ADJUST SKB
            skb->dev = entry->dev;

                    // SEND SKB
            sendkb(skb);
        }

        return DHCP_HANDLED;

        } elif (entry->leaseProtocol == skb->protocol
                && entry->leaseMinSize <= skb->len) {

            if (entry->flags & TEMQUE_SER_SRV_MAC)
                if (memcmp(entry->srvMAC, seila, ETH_ALEN))
                    return 0;

            // NOTE: AQUI SO COPIA A RESPOSTA, E APLICA SO NO KEEPER
            if (enry->flags & IS_DHCP4)  {
                // DHCP 4

                if (entry->xid != msg->xid)
                    return 0;

                if (entry->flags & TEMQUE_SER_SRV_IP)
                    if (entry->v4.srv != msg->sip)
                        return 0;

            } else {
                // DHCP 6

                if (entry->xid != msg->xid)
                    return 0;

                if (entry->flags & TEMQUE_SER_SRV_IP)
                    if (memcmp(entry->v6.srv, msg->sip, 16))
                        return 0;

                if (entry->flags & TEMQUE_SER_LLP)
                    if (memcmp(entry->v6.ll, msg->dip, 16))
                        return 0;
            }


    // NO KEEPER:
            switch (entry->status) {

                case LEASE_STATUS_DHCP_4_0:

                    break;

                case LEASE_STATUS_DHCP_4_1:

                    break;

                case LEASE_STATUS_DHCP_6_1:

                    break;

                case LEASE_STATUS_DHCP_6_2:

                    break;

                case LEASE_STATUS_RA:

                    if () {
                        // ALGO MUDOU:
                        // gw6, gwmac, prefixo, prefix length, mtu
                            // APRENDE
                    }

                    break;
            }
        }
    }

}

#endif
