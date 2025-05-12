
static int __cold_as_ice __optimize_size dev_up (net_device_s* const dev) {

    // TODO: ATIVA O TIMER
    printk("XGW: UP\n");

    return 0;
}

static int __cold_as_ice __optimize_size dev_down (net_device_s* const dev) {

    // TODO: DESATIVA O TIMER
    printk("XGW: DOWN\n");

    return 0;
}

static const net_device_ops_s xgwDevOps = {
    .ndo_init             =  NULL,
    .ndo_open             =  dev_up,
    .ndo_stop             =  dev_down,
    .ndo_start_xmit       =  out,
    .ndo_set_mac_address  =  NULL,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void __cold_as_ice __optimize_size dev_setup (net_device_s* const dev) {

    dev->netdev_ops      = &xgwDevOps;
    dev->header_ops      = NULL;
    dev->type            = ARPHRD_NONE;
    dev->addr_len        = 0; // TODO: 2 nodeSelf ?
    dev->hard_header_len = 0;
//  dev->min_header_len  = 0;
    dev->needed_headroom = XGW_HEADROOM;
    dev->min_mtu         = XGW_PAYLOAD_MIN;
    dev->max_mtu         = XGW_PAYLOAD_MAX;
    dev->mtu             = XGW_PAYLOAD_MAX; // TODO: DETAULT ETH_MTU - (PKT_X_SIZE + PKT_ALIGN_SIZE)
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

// TODO: INTERCEPT MTU CHANGES TO ALLOW ONLY THE NODE/GLOBAL MTU

// CREATE A INTERFACE FOR A NODE
static inline net_device_s* dev_create_node (const char* const name, const uint nid) {

    // CREATE THE VIRTUAL INTERFACE
    net_device_s* const dev = alloc_netdev(sizeof(uint), name, NET_NAME_USER, dev_setup);

    if (dev == NULL) {
        printk("XGW: FAILED TO ALLOCATE\n");
        return NULL;
    }

    *(uint*)netdev_priv(dev) = nid;

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(dev)) {
        // TODO: FREE
        printk("XGW: CREATE FAILED TO REGISTER\n");
        return NULL;
    }

    return dev;
}
