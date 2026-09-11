
static netdev_tx_t out (skb_s* const skb, net_device_s* const dev) {

    ASSERT(dev == clf);

    if (skb_is_nonlinear(skb))
        goto _drop;

    pkt_s* const pkt = SKB_NETWORK(skb) - offsetof(pkt_s, iVersion);

    // CURRENT PATH ID BEING USED
    const uint oid = skb->mark % PATHS_N;

    const uint sid = __ctz((opaths >> oid) << oid) % PATHS_N;

    path_s* const path = &paths[sid];

    ASSERT(path->phys);
    ASSERT(path->eSize == (sizeof(path->encap) - path->eOffset));
    ASSERT(path->eSize <= ENCAP_SIZE);
    ASSERT(path->nOffset >= ENCAP_SIZE);
    ASSERT(path->eOffset <= path->nOffset);

    if ((PTR(&pkt->encap) + path->eOffset) < SKB_HEAD(skb))
        goto _drop;

    // COPY THE ENCAPSULEMENT
    memcpy(PTR(&pkt->encap) + path->eOffset,
           PTR(&path->encap) + path->eOffset,
         sizeof(path->encap) - path->eOffset);

    // ADJUST DYNAMIC ENCAPSULEMENT FIELDS
    if (path->pword)
          pkt->encap.w16[path->pword] = BE16(skb->len + 2);

    // TODO: ADJUST LOCAL PORT ACORDING TO MARK

    // IP CHECKSUM

    // UDP CHECKSUM
    pkt->uChk = BE16(0);

    //
    skb->dev = path->phys;
    skb->mark = 0;
    skb->len      += path->eSize;
    skb->mac_len   = path->mac_len;
    skb->protocol  = path->protocol;

    // skb_set_mac_header / skb_reset_mac_header
    // skb_set_network_header / skb_reset_network_header
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header       = (PTR(pkt) + path->eOffset) - SKB_HEAD(skb);
    skb->network_header   = (PTR(pkt) + path->nOffset) - SKB_HEAD(skb);
#else
    skb->mac_header       =  PTR(pkt) + path->eOffset;
    skb->network_header   =  PTR(pkt) + path->nOffset;
#endif
    skb->data             =  PTR(pkt) + path->eOffset;

#if 1
    if (skb->ip_summed == CHECKSUM_PARTIAL)
        if (skb_checksum_help(skb))
            goto _drop;
#else
    skb->ip_summed = CHECKSUM_NONE;
#endif

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    dev_queue_xmit(skb);
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED

    return NETDEV_TX_OK;

_drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}
