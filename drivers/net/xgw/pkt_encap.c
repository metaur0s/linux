
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

    //
    random64_n(pkt->p, PKT_ALIGN_WORDS, SUFFIX_ULL(CONFIG_XGW_RANDOM_ENCRYPT_ALIGN));

    //
    pkt->x.dsize   = BE16(size);
    pkt->x.version = BE8(node->oVersions[o]);
    pkt->x.time    = BE64(rtime);
    pkt->x.hash    = BE64(pkt_encrypt(node, o, pkt, size));

    pkt_encap_finish(pkt, size);
}
