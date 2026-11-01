
static int __cold_as_ice __optimize_size dev_up (net_device_s* const dev) {

    printk("CLF: UP\n");

    return 0;
}

static int __cold_as_ice __optimize_size dev_down (net_device_s* const dev) {

    printk("CLF: DOWN\n");

    return 0;
}

static const net_device_ops_s clfDevOps = {
    .ndo_init             =  NULL,
    .ndo_open             =  dev_up,
    .ndo_stop             =  dev_down,
    .ndo_start_xmit       =  out,
    .ndo_set_mac_address  =  NULL,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void __cold_as_ice __optimize_size dev_setup (net_device_s* const dev) {

    dev->netdev_ops      = &clfDevOps;
    dev->header_ops      = NULL;
    dev->type            = ARPHRD_NONE;
    dev->addr_len        = 0; // TODO: 2 nodeSelf ?
    dev->hard_header_len = 0;
//    dev->min_header_len  = 0;
    dev->needed_headroom = CLF_HEADROOM;
    dev->min_mtu         = CLF_PAYLOAD_MIN;
    dev->max_mtu         = CLF_PAYLOAD_MAX;
    dev->mtu             = CLF_PAYLOAD_MAX;
    dev->tx_queue_len    = 0; // DEFAULT_TX_QUEUE_LEN
    dev->flags           = 0
        | IFF_POINTOPOINT
        | IFF_NOARP
        ;
    dev->priv_flags |= 0
        | IFF_NO_QUEUE
        | IFF_NO_RX_HANDLER
        | IFF_LIVE_ADDR_CHANGE
        ;
    dev->lltx = true; // dev->features |= NETIF_F_LLTX
    dev->features |= 0
        | NETIF_F_RXCSUM
        | NETIF_F_HW_CSUM
#if 0
        | NETIF_F_HIGHDMA
#endif
        ;
    dev->hw_features |= 0
        | NETIF_F_RXCSUM
        | NETIF_F_HW_CSUM
#if 0
        | NETIF_F_HIGHDMA
#endif
        ;
    // TODO: hw_enc_features ?
    //
}
