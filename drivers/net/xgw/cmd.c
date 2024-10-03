
// TODO: VAI TER QUE PASSAR O COMANDO ALINHADO,
// TODO: E AO INVES DE COPIAR SIMPLESMENTE LER
//      (ou copiar os primeiros 64 bytes) e se for key, copiar o restante

static inline uint gid_of_nid (const uint nid) {

    for (uint i = 0; i != gwsN; i++)
        if (gws[i] == nid)
            return i;

    // NOT FOUND
    return GWS_N;
}

#define MAC(m) \
    (uint)(m)[0], (uint)(m)[1], (uint)(m)[2], \
    (uint)(m)[3], (uint)(m)[4], (uint)(m)[5]

#define _PRINT_IP4(a) \
    (uint)(a)[0], (uint)(a)[1], \
    (uint)(a)[2], (uint)(a)[3]

#define _PRINT_IP6(a) \
    (uint)BE16((a)[0]), (uint)BE16((a)[1]), (uint)BE16((a)[2]), (uint)BE16((a)[3]), \
    (uint)BE16((a)[4]), (uint)BE16((a)[5]), (uint)BE16((a)[6]), (uint)BE16((a)[7])

#define _PRINT_KEYS(K) \
    (uintll)((K)[0]), \
    (uintll)((K)[1]), \
    (uintll)((K)[2]), \
    (uintll)((K)[3]), \
    (uintll)((K)[4]), \
    (uintll)((K)[5]), \
    (uintll)((K)[6]), \
    (uintll)((K)[7])

#define _PRINT_SINCE(since) ((get_jiffies_64() - (since))/HZ)

#define        _CMD_ERR(x)   e = ___JOIN(CMD_ERR_, x) - 200
#define         CMD_ERR(x) { e = ___JOIN(CMD_ERR_, x) - 200; goto failed;         }
#define    FREE_CMD_ERR(x) { e = ___JOIN(CMD_ERR_, x) - 200; goto failed_free;    }
#define NOTHING_CMD_ERR(x) { e = ___JOIN(CMD_ERR_, x) - 200; goto failed_nothing; }
#define     CMD_SUCCESS()                                    goto failed

// TODO: VERIFICAR ESSA PORRA AQUI
#define _CMD_SIZE(m) (offsetof(cmd_arg_s, m) + sizeof(cmd->m))
#define _CMD_SIZE_VAR        0 // LEMBRAR DE VERIFICAR EMBAIXO TAMBEM
#define _CMD_SIZE_NODE      (sizeof(cmd->nid))
#define _CMD_SIZE_PATH      (sizeof(cmd->nid) + sizeof(cmd->pid))
#define _CMD_SIZE_DHCP      (sizeof(cmd->did))
#define _CMD_SIZE_PORTS      sizeof(cmd->ports[0])
#define _CMD_SIZE_NOTHING   0

#define _CMD_CONSUME(_member) cmd = PTR(cmd) + sizeof(cmd->_member); size -= sizeof(cmd->_member)

static ssize_t __cold_as_ice __optimize_size cmd (struct file *file, const char __user *ubuf, size_t size, loff_t *ppos) {

    // TODO:
//    *ppos += size;

    int e = size;

    net_device_s* phys = NULL;

    node_s* node; uint nid;
    path_s* path; uint pid; uint portsN;

    // TAMANHO MINIMO DA MENSAGEM
    // TAMANHO MAXIMO DA MENSAGEM
    if (size < CMD_SIZE_MIN ||
        size > CMD_SIZE_MAX)
        NOTHING_CMD_ERR(INVALID_CMD_SIZE);

    void* const buff = kmalloc(size, GFP_NOWAIT);

    if (buff == NULL)
        NOTHING_CMD_ERR(ALLOC_CMD);

    if (copy_from_user(buff, ubuf, size))
        FREE_CMD_ERR(COPY_CMD);

    const cmd_arg_s* cmd = buff;

    const uint C = cmd->code; _CMD_CONSUME(code);

    if (C >= CMDS_N)
        FREE_CMD_ERR(INVALID_CMD_CODE);

    // CHECK IF THE COMMAND MESSAGE IS COMPLETE
    // THE FLAGS WILL IMPLY READING THINGS
    static const u32 cmdSizes [CMDS_N] = {
        [CMD_PORT_ON]              = _CMD_SIZE_PORTS,
        [CMD_PORT_OFF]             = _CMD_SIZE_PORTS,
        [CMD_PORT_GET]             = _CMD_SIZE_PORTS,
        [CMD_PORTS_LIST]           = _CMD_SIZE_NOTHING,
        [CMD_PORTS_CLEAR]          = _CMD_SIZE_NOTHING,
        [CMD_PHYS_ATTACH]          = _CMD_SIZE(phys),
        [CMD_PHYS_DETACH]          = _CMD_SIZE(phys),
        [CMD_PHYS_LIST]            = _CMD_SIZE_NOTHING,
        [CMD_SELF_SET]             = _CMD_SIZE(nid),
        [CMD_SELF_GET]             = _CMD_SIZE_NOTHING,
        [CMD_GWS_INSERT]           = _CMD_SIZE(nid),
        [CMD_GWS_REMOVE]           = _CMD_SIZE(nid),
        [CMD_GWS_LIST]             = _CMD_SIZE_NOTHING,
        [CMD_GWS_CLEAR]            = _CMD_SIZE_NOTHING,
        [CMD_NODE_NEW]             = _CMD_SIZE_NODE,
        [CMD_NODE_DEL]             = _CMD_SIZE_NODE,
        [CMD_NODE_SET_NAME]        = _CMD_SIZE(nname),
        [CMD_NODE_SET_MTU]         = _CMD_SIZE(mtu),
        [CMD_NODE_SET_CONNS_N]     = _CMD_SIZE(connsN),
        [CMD_NODE_SET_SECRET]      = _CMD_SIZE_VAR,
        [CMD_NODE_CLR_NAME]        = _CMD_SIZE_NODE,
        [CMD_NODE_CLR_SECRET]      = _CMD_SIZE_NODE,
        [CMD_NODE_ON]              = _CMD_SIZE_NODE,
        [CMD_NODE_OFF]             = _CMD_SIZE_NODE,
        [CMD_NODE_STATUS]          = _CMD_SIZE_NODE,
        [CMD_NODE_STATS]           = _CMD_SIZE_NODE,
        [CMD_PATH_NEW]             = _CMD_SIZE_PATH,
        [CMD_PATH_DEL]             = _CMD_SIZE_PATH,
        [CMD_PATH_SET_NAME]        = _CMD_SIZE(pname),
        [CMD_PATH_SET_WEIGHT_NODE] = _CMD_SIZE(weight_node),
        [CMD_PATH_SET_WEIGHT_ACKS] = _CMD_SIZE(weight_acks),
        [CMD_PATH_SET_CLIENT]      = _CMD_SIZE(nid),
        [CMD_PATH_SET_SERVER]      = _CMD_SIZE(nid),
        [CMD_PATH_SET_TIMEOUT]     = _CMD_SIZE(timeout),
        [CMD_PATH_SET_RTT_MIN]     = _CMD_SIZE(rtt),
        [CMD_PATH_SET_RTT_MAX]     = _CMD_SIZE(rtt),
        [CMD_PATH_SET_RTT_VAR]     = _CMD_SIZE(rtt),
        [CMD_PATH_SET_DHCP]        = _CMD_SIZE(did),
        [CMD_PATH_SET_PHYS]        = _CMD_SIZE(phys),
        [CMD_PATH_SET_TYPE]        = _CMD_SIZE(type),
        [CMD_PATH_SET_VLAN_PROTO]  = _CMD_SIZE(eProto),
        [CMD_PATH_SET_VLAN_ID]     = _CMD_SIZE(vID),
        [CMD_PATH_SET_ETH_SRC]     = _CMD_SIZE(mac),
        [CMD_PATH_SET_ETH_DST]     = _CMD_SIZE(mac),
        [CMD_PATH_SET_IP4_TOS]     = _CMD_SIZE(tos),
        [CMD_PATH_SET_IP6_TOS]     = _CMD_SIZE(tos),
        [CMD_PATH_SET_IP4_TTL]     = _CMD_SIZE(ttl),
        [CMD_PATH_SET_IP6_TTL]     = _CMD_SIZE(ttl),
        [CMD_PATH_SET_IP4_SRC]     = _CMD_SIZE(addr4),
        [CMD_PATH_SET_IP6_SRC]     = _CMD_SIZE(addr6),
        [CMD_PATH_SET_IP4_DST]     = _CMD_SIZE(addr4),
        [CMD_PATH_SET_IP6_DST]     = _CMD_SIZE(addr6),
        [CMD_PATH_SET_UDP_SRC]     = _CMD_SIZE_PATH          + _CMD_SIZE_PORTS,
        [CMD_PATH_SET_UDP_DST]     = _CMD_SIZE_PATH          + _CMD_SIZE_PORTS,
        [CMD_PATH_SET_TCP_SRC]     = _CMD_SIZE_PATH          + _CMD_SIZE_PORTS,
        [CMD_PATH_SET_TCP_DST]     = _CMD_SIZE_PATH          + _CMD_SIZE_PORTS,
        [CMD_PATH_SET_PPP_SESSION] = _CMD_SIZE_PATH + 2,
        [CMD_PATH_CLR_NAME]        = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_WEIGHT_NODE] = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_WEIGHT_ACKS] = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_DHCP]        = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_PHYS]        = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_TYPE]        = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_VLAN_PROTO]  = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_VLAN_ID]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_ETH_SRC]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_ETH_DST]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_IP4_TOS]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_IP4_TTL]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_IP4_SRC]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_IP4_DST]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_IP6_TOS]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_IP6_TTL]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_IP6_SRC]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_IP6_DST]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_UDP_SRC]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_UDP_DST]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_TCP_SRC]     = _CMD_SIZE_PATH,
        [CMD_PATH_CLR_TCP_DST]     = _CMD_SIZE_PATH,
        [CMD_PATH_ON]              = _CMD_SIZE_PATH,
        [CMD_PATH_OFF]             = _CMD_SIZE_PATH,
        [CMD_PATH_STATUS]          = _CMD_SIZE_PATH,
        [CMD_PATH_STATS]           = _CMD_SIZE_PATH,
        [CMD_STATS]                = _CMD_SIZE_NOTHING,
        [CMD_NMAP]                 = sizeof(cmd->nid) + sizeof(cmd->nid2),
    };

    if (cmdSizes[C] > size)
        FREE_CMD_ERR(INVALID_CMD_SIZE);

    if (C_USE_NID(C)) {
        if ((nid = cmd->nid) >= NODES_N)
            FREE_CMD_ERR(INVALID_NID);
        _CMD_CONSUME(nid);
    }

    if (C_USE_PID(C)) {
        if ((pid = cmd->pid) >= PATHS_N)
            FREE_CMD_ERR(INVALID_PID);
        _CMD_CONSUME(pid);
    }

    if (C_USE_PORTS(C)) {
        if (size % sizeof(cmd->ports[0]))
            FREE_CMD_ERR(INVALID_CMD_SIZE);
        portsN = size / sizeof(cmd->ports[0]);
    }

    // LOCK
    unsigned long iflags;

    spin_lock_irqsave(&xlock, iflags);

    if (C_USE_NODE(C)) {
        // REFERS TO A NODE ENTRY

        if (nid == nodeSelf)
            CMD_ERR(NODE_IS_SELF);

        node = (node_s*)((uintptr_t)nodes[nid] & ~(uintptr_t)1);

        if (node) {

            ASSERT(node->nid == nid);

            // TO BE ON, MUST BE FULL
            ASSERT(!((node->info & N_ON) && (node->info != (N_ON | N_NAME | N_SECRET | N_CONNS_N | N_MTU))));

            // IF ON, MUST BE RUNNING
            ASSERT(!((node->info & N_ON) && !node->ptr));

            if (C_NODE_MUST_NOT_EXIST(C))
                CMD_ERR(NODE_EXIST);

            if (C == CMD_NODE_ON) {
                if (node->info & N_ON)
                    CMD_SUCCESS();
            }

            if (C_NODE_MUST_BE_OFF_IDLE(C)) {
                if (node->info & N_ON)
                    CMD_ERR(NODE_IS_ON);
                if (node->ptr)
                    CMD_ERR(NODE_IS_STOPPING); // DEVERIA SER 0? +delay/sleep
                // THE NODE IS OFF AND IDLE
                ASSERT(!(node->info & N_ON));
                ASSERT(node->ptr == NULL);
                ASSERT(!node->kpaths);
                ASSERT(!node->ipaths);
                ASSERT(!node->opaths);
                //ASSERT(node != nodes[nid]);
            }

        } elif (C != CMD_NODE_NEW)
            // OPERA SOMENTE EM NODES QUE EXISTEM
            CMD_ERR(NODE_DONT_EXIST);
    }

    if (C_USE_PATH(C)) {
        // REFERS TO A PATH

        path = &node->paths[pid];

        if (path->info) {

            ASSERT(path->nid == nid);
            ASSERT(path->pid == pid);

            ASSERT(path->info & P_EXIST);
            ASSERT((path->info & (P_CLIENT | P_SERVER)) != (P_CLIENT | P_SERVER));
            ASSERT(path->info <= P_ALL);
            ASSERT(path->sPortsN <= PATH_PORTS_N);
            ASSERT(path->dPortsN <= PATH_PORTS_N);

            // PARAMETERS
            ASSERT(!((path->info & P_PHYS   ) && !path->skel.phys));
            //ASSERT(!((path->info & P_PORT_SRC) && !path->sPortsN));
            //ASSERT(!((path->info & P_PORT_DST) && !path->dPortsN));

            // I/O DISABLED WHILE IDLE
            ASSERT(!(((path->info & P_INFO) == path->info) && (node->ipaths & IPATH(pid))));
            ASSERT(!(((path->info & P_INFO) == path->info) && (node->opaths & OPATH(pid))));

            // I/O ACCORDING TO STATUS
            ASSERT(!((path->info & K_START)      && (node->ipaths  & IPATH(pid))));
            ASSERT(!((path->info & K_START)      && (node->opaths  & OPATH(pid))));
            ASSERT(!((path->info & K_SUSPENDING) && (node->opaths  & OPATH(pid))));
            ASSERT(!((path->info & K_SUSPENDING) && (node->ipaths  & IPATH(pid))));
            ASSERT(!((path->info & K_LISTEN)     && !(node->ipaths & IPATH(pid))));
            ASSERT(!((path->info & K_LISTEN)     && (node->opaths  & OPATH(pid))));
            ASSERT(!((path->info & K_ESTABLISHED) && !(node->ipaths & IPATH(pid))));

            // IF ON, MUST BE RUNNING (EXCEPT IF NODE IS OFF)
            ASSERT(!((path->info & P_ON) && (node->info & N_ON) && !(node->kpaths & KPATH(pid))));

            // RUNNING BUT GOING IDLE
            // RUNNING AND NOT IDLE
            // NOT RUNNING AND IDLE
            ASSERT(((path->info & P_INFO) == path->info) || (node->kpaths & KPATH(pid)));

            if (C_PATH_MUST_NOT_EXIST(C))
                CMD_ERR(PATH_EXIST);

            if (C_PATH_MUST_BE_OFF_IDLE(C)) {
                if (path->info & P_ON)
                    CMD_ERR(PATH_IS_ON);
                if (node->kpaths & KPATH(pid))
                    CMD_ERR(PATH_IS_STOPPING); // DEVERIA SER 0? +delay/sleep
                // THE PATH IS OFF AND IDLE
                ASSERT(!(path->info & ~P_INFO));
                ASSERT(path->_skb == NULL);
                ASSERT(!(node->kpaths & KPATH(pid)));
                ASSERT(!(node->ipaths & IPATH(pid)));
                ASSERT(!(node->opaths & OPATH(pid)));
            }

        } elif (C != CMD_PATH_NEW)
            // OPERA SOMENTE EM PATHS QUE EXISTEM
            CMD_ERR(PATH_DONT_EXIST);
    }

    if (C_USE_PHYS(C)) {
        // MUST HAVE A VALID NAME
        if (!cmd->phys[0] ||
             cmd->phys[IFNAMSIZ - 1])
            CMD_ERR(INVALID_PHYS);
        // LOOKUP IT, OWNED
        phys = dev_get_by_name(&init_net, cmd->phys);
        // MUST EXIST
        if (phys == NULL)
            CMD_ERR(PHYS_NOT_FOUND);
        // CANNOT BE THE VPN ITSELF
        if (phys == xgw)
            CMD_ERR(PHYS_IS_XGW);
        // VALIDATE INTERFACE TYPE, FLAGS ETC
        if (0)
            CMD_ERR(PHYS_IS_BAD);
        _CMD_CONSUME(phys);
    }

    //
    BUILD_ASSERT(sizeof(cmd->nname) == sizeof(node->name));
    BUILD_ASSERT(sizeof(cmd->pname) == sizeof(path->name));

    BUILD_ASSERT(sizeof(cmd->addr4) == sizeof(path->skel.encap_ip4.ip4.saddr));
    BUILD_ASSERT(sizeof(cmd->addr4) == sizeof(path->skel.encap_ip4.ip4.daddr));
    BUILD_ASSERT(sizeof(cmd->addr6) == sizeof(path->skel.encap_ip6.ip6.saddr));
    BUILD_ASSERT(sizeof(cmd->addr6) == sizeof(path->skel.encap_ip6.ip6.daddr));

    BUILD_ASSERT(sizeof(cmd->mac) == sizeof(path->skel.encap_eth.eth.dmac));
    BUILD_ASSERT(sizeof(cmd->mac) == sizeof(path->skel.encap_eth.eth.smac));

    //
    switch (C) {
        case CMD_PATH_SET_ETH_DST:
        case CMD_PATH_CLR_ETH_SRC:
        case CMD_PATH_SET_ETH_SRC:
        case CMD_PATH_CLR_ETH_DST:
            if (!path_is_eth(path))
                CMD_ERR(PATH_NOT_ETH);
            break;
        case CMD_PATH_SET_VLAN_PROTO:
        case CMD_PATH_CLR_VLAN_PROTO:
        case CMD_PATH_SET_VLAN_ID:
        case CMD_PATH_CLR_VLAN_ID:
            if (!path_is_vlan(path))
                CMD_ERR(PATH_NOT_VLAN);
            ASSERT(path_is_eth(path));
            break;
        case CMD_PATH_SET_IP4_TOS:
        case CMD_PATH_CLR_IP4_TOS:
        case CMD_PATH_SET_IP4_TTL:
        case CMD_PATH_CLR_IP4_TTL:
        case CMD_PATH_SET_IP4_SRC:
        case CMD_PATH_CLR_IP4_SRC:
        case CMD_PATH_SET_IP4_DST:
        case CMD_PATH_CLR_IP4_DST:
            if (!path_is_ip4(path))
                CMD_ERR(PATH_NOT_IP4);
            break;
        case CMD_PATH_SET_IP6_TOS:
        case CMD_PATH_CLR_IP6_TOS:
        case CMD_PATH_SET_IP6_TTL:
        case CMD_PATH_CLR_IP6_TTL:
        case CMD_PATH_SET_IP6_SRC:
        case CMD_PATH_CLR_IP6_SRC:
        case CMD_PATH_SET_IP6_DST:
        case CMD_PATH_CLR_IP6_DST:
            if (!path_is_ip6(path))
                CMD_ERR(PATH_NOT_IP6);
            break;
        case CMD_PATH_SET_IP_TOS:
        case CMD_PATH_SET_IP_TTL:
            if (!(path->info & P_SERVER))
                CMD_ERR(PATH_NOT_SERVER);
            break;
        case CMD_PATH_SET_UDP_SRC:
        case CMD_PATH_CLR_UDP_SRC:
        case CMD_PATH_SET_UDP_DST:
        case CMD_PATH_CLR_UDP_DST:
            if (!path_is_udp(path))
                CMD_ERR(PATH_NOT_UDP);
            break;
        case CMD_PATH_SET_TCP_SRC:
        case CMD_PATH_CLR_TCP_SRC:
        case CMD_PATH_SET_TCP_DST:
        case CMD_PATH_CLR_TCP_DST:
            if (!path_is_tcp(path))
                CMD_ERR(PATH_NOT_TCP);
            break;
        case CMD_PATH_SET_PPP_SESSION:
            if (!path_is_ppp(path))
                CMD_ERR(PATH_NOT_PPP);
            break;
    }

    //
    switch (C) {
        case CMD_PATH_SET_UDP_SRC:
        case CMD_PATH_SET_UDP_DST:
        case CMD_PATH_SET_TCP_SRC:
        case CMD_PATH_SET_TCP_DST:
            if (portsN > PATH_PORTS_N)
                CMD_ERR(INVALID_PORTS_N);
            break;
        case CMD_PORT_ON:
        case CMD_PORT_OFF:
        case CMD_PORT_GET:
            if (portsN > UDP_PORTS_N)
                CMD_ERR(INVALID_PORTS_N);
            break;
    }

    switch ((enum CMD)C) {

        case CMD_PORT_ON: {

            while (portsN--)
                ports_enable(cmd->ports[portsN]);

        } break;

        case CMD_PORT_OFF: {

            while (portsN--)
                ports_disable(cmd->ports[portsN]);

        } break;

        case CMD_PORTS_CLEAR: {

            for_count (p, PORTS_N)
                ports_disable(p);

        } break;

        case CMD_PORT_GET: {

        } break;

        case CMD_PORTS_LIST: {

        } break;

        case CMD_PHYS_ATTACH: { // TODO: USAGE COUNT NOS HOOKS

            rtnl_lock();

            if (!phys->xgw) {
                phys->xgw = true;
                // KEEP HOLDING IT
                phys = NULL;
            }

            rtnl_unlock();

        } break;

        case CMD_PHYS_DETACH: {

            rtnl_lock();

            if (phys->xgw) {
                phys->xgw = false;
                // RELEASE AGAIN THE DEVICE
                dev_put(phys);
            }

            rtnl_unlock();

        } break;

        case CMD_PHYS_LIST: {

        } break;

        case CMD_SELF_SET: {

            nodeSelf = nid;

            // TODO: FIXME: FIX EVERYTHING

        } break;

        case CMD_SELF_GET: {

            printk("XGW: SELF: %u\n", (uint)nodeSelf);

        } break;

        case CMD_GWS_INSERT: {

            if (gid_of_nid(nid) != GWS_N)
                // JA TEM
                CMD_ERR(GWS_NID_ALREADY);

            if (gwsN == GWS_N)
                // FULL
                CMD_ERR(GWS_FULL);

            // POE ELE NO FINAL
            gws[gwsN++] = nid;

        } break;

        case CMD_GWS_REMOVE: {

            const uint gid = gid_of_nid(nid);

            if (gid == GWS_N)
                // NAO TEM
                CMD_ERR(GWS_NID_NOT_FOUND);

            // ARRASTA O ULTIMO PARA CIMA DELE
            gws[gid] = gws[--gwsN];

        } break;

        // TODO: CMD_GWS_INDEX get gw index of node

        case CMD_GWS_LIST: {

            printk("XGW: HAS %u GWS\n", (uint)gwsN);

            for (uint i = 0; i != gwsN; i++)
                printk("XGW: GW [%u] -> %u\n", i, (uint)gws[i]);

        } break;

        case CMD_GWS_CLEAR: {

        } break;

        case CMD_PATH_DEL: {

            node->weights -= path->weight;

            // REMOVE P_EXIST AND K_*
            memset(path, 0, sizeof(path_s));

        } break;

        case CMD_PATH_ON: {

            uint pinfo = path->info;

            if (!(pinfo & P_ON)) {

                // INFORMACOES QUE SAO NECESSARIAS TO START A PATH
                if (!(pinfo & P_NAME   )) CMD_ERR(PATH_NEED_NAME);
                if (!(pinfo & (P_CLIENT | P_SERVER)))
                                          CMD_ERR(PATH_NEED_CLT_SRV);
                if (!(pinfo & P_TIMEOUT)) CMD_ERR(PATH_NEED_TIMEOUT);
                if (!(pinfo & P_RTT_MIN)) CMD_ERR(PATH_NEED_RTT_MIN);
                if (!(pinfo & P_RTT_MAX)) CMD_ERR(PATH_NEED_RTT_MAX);
                if (!(pinfo & P_RTT_VAR)) CMD_ERR(PATH_NEED_RTT_VAR);

                //
                ASSERT((pinfo & (P_CLIENT | P_SERVER))
                             != (P_CLIENT | P_SERVER));

                //
                if (path->rtt_min > path->rtt_max)
                    CMD_ERR(INVALID_RTT_RANGE);

                if ((path->rtt_min + path->rtt_var) < PATH_RTT_EFFECTIVE_MIN)
                    CMD_ERR(INVALID_RTT_RANGE);

                if ((path->rtt_max + path->rtt_var) > PATH_RTT_EFFECTIVE_MAX)
                    CMD_ERR(INVALID_RTT_RANGE);

                const uint type = path->skel.type;

                if (pinfo & P_SERVER) {
                    // SERVER

                    if (!(pinfo & P_TOS)) CMD_ERR(PATH_NEED_TOS);
                    if (!(pinfo & P_TTL)) CMD_ERR(PATH_NEED_TTL);

                    // ON SERVER MODE, THOSE WILL BE OVERWRITTEN ANYWAY
                    pinfo &= ~(P_PHYS | P_DHCP | P_DHCP_MAC_DST_SERVER | P_DHCP_MAC_DST_GW | __P_TYPE_CLR);

                } else {
                    // CLIENT

                    if (pinfo & P_DHCP) {
                        // USING DHCP

                        if (type & __IP4) {
                            if (1)
                                // O PATH É IPV4 E O DHCP NÃO É IPV4
                                CMD_ERR(PATH_USE_DHCP_NOT_IP_4);
                        } elif (type & __IP6) {
                            if (1)
                                // O PATH É IPV6 E O DHCP NÃO É IPV6
                                CMD_ERR(PATH_USE_DHCP_NOT_IP_6);
                        } else // O PATH NÃO É IP E USA DHCP
                                CMD_ERR(PATH_USE_DHCP_NOT_IP);

                        //
                        pinfo |= P_PHYS;
                        // type & __ETH
                        pinfo |= P_MAC_SRC;
                        // type & __VLAN
                        pinfo |= P_VPROTO;
                        pinfo |= P_VID;
                        pinfo |= P_ADDR_SRC;

                        // VAI TER QUE VERIFICAR O TAL DHCP AQUI
                        // E CARREGAR O QUE ELE CONTEM: __VLAN, __ETH, ETC
                        //     tem que dar match no path->skel.type e no dhcp->type

                        //      se tiver __ETH, carregar o pinfo |= P_MAC_SRC
                        //      se tiver __ETH, carregar o pinfo |= P_MAC_DST (GW / SERVER) SE O P_DHCP_ETH_DST_XXX ESTIVER SETADO
                        //      se tiver __IP4, carregar o pinfo |= P_ADDR_SRC
                        if (pinfo & (P_DHCP_MAC_DST_SERVER | P_DHCP_MAC_DST_GW))
                            pinfo |= P_MAC_DST;

                        //  marcar o dhcp->users++
                        //      e assim enquanto tiver paths P_ON com tal dhcp, nao pode mudar o tipo dele, e nem deleta-lo
                    }

                    if (!(pinfo & P_PHYS)) CMD_ERR(PATH_NEED_PHYS);

                    if (type & __ETH) {
                        if (!(pinfo & P_MAC_SRC)) CMD_ERR(PATH_NEED_MAC_SRC);
                        if (!(pinfo & P_MAC_DST)) CMD_ERR(PATH_NEED_MAC_DST);
                    }

                    if (type & __VLAN) {
                        if (!(pinfo & P_VPROTO)) CMD_ERR(PATH_NEED_VLAN_PROTO);
                        if (!(pinfo & P_VID))    CMD_ERR(PATH_NEED_VLAN_ID);
                    }

                    if (type & (__IP4 | __IP6)) {
                        if (!(pinfo & P_TOS))      CMD_ERR(PATH_NEED_TOS);
                        if (!(pinfo & P_TTL))      CMD_ERR(PATH_NEED_TTL);
                        if (!(pinfo & P_ADDR_SRC)) CMD_ERR(PATH_NEED_ADDR_SRC);
                        if (!(pinfo & P_ADDR_DST)) CMD_ERR(PATH_NEED_ADDR_DST);
                    }

                    if (type & (__UDP | __TCP)) {
                        if (!(pinfo & P_PORT_SRC)) CMD_ERR(PATH_NEED_PORT_SRC);
                        if (!(pinfo & P_PORT_DST)) CMD_ERR(PATH_NEED_PORT_DST);
                    }

                    // ON DHCP MODE, THOSE WILL BE OVERWRITTEN ANYWAY
                    if (pinfo & P_DHCP)
                        pinfo &= ~(P_PHYS | P_MAC_SRC | P_ADDR_SRC | P_VPROTO | P_VID);
                    if (pinfo & (P_DHCP_MAC_DST_SERVER | P_DHCP_MAC_DST_GW))
                        pinfo &= ~P_MAC_DST;
                }

                // IF THE NODE IS ON, START THE PATH NOW
                if (node->info & N_ON) {
                    node->kpaths |= KPATH(pid);
                    pinfo |= K_START;
                }

                path->info = pinfo | P_ON;
            }

        } break;

        case CMD_PATH_OFF: {

            if (path->info & P_ON)
                path->info ^= P_ON;
            if (path->info & (K_START | K_LISTEN | K_ESTABLISHED))
                path->info = (path->info & P_INFO) | K_SUSPEND;

        } break;

        case CMD_PATH_CLR_WEIGHT_NODE: {

            node->weights -= path->weight;
            path->weight   = 0;

        } break;

        case CMD_PATH_CLR_WEIGHT_ACKS: { // TODO:

            path->weight_acks = 0;

        } break;

        case CMD_NODE_STATUS: {

            printk("XGW: %s: ID %u\n",            node->name, (uint  )node->nid);
            printk("XGW: %s: KPATHS %04X\n",      node->name, (uint  )node->kpaths);
            printk("XGW: %s: IPATHS %04X\n",      node->name, (uint  )node->ipaths);
            printk("XGW: %s: OPATHS %016llX\n",   node->name, (uintll)node->opaths);

            printk("XGW: %s: MTU %u\n",           node->name, (uint  )node->mtu);
            printk("XGW: %s: CONNS N %u\n",       node->name, (uint  )node->connsN);
            printk("XGW: %s: WEIGHTS %u\n",       node->name, (uint  )node->weights);
            printk("XGW: %s: LCOUNTER %016llX\n", node->name, (uintll)node->lcounter);
            printk("XGW: %s: RCOUNTER %016llX\n", node->name, (uintll)node->rcounter);

            printk("XGW: %s: INFO: 0x%02X %s%s%s%s%s\n", node->name,
               (uint)node->info,
                    (node->info & N_ON      ) ? " ON"      : "",
                    (node->info & N_NAME    ) ? " NAME"    : "",
                    (node->info & N_MTU     ) ? " MTU"     : "",
                    (node->info & N_CONNS_N ) ? " CONNS-N" : "",
                    (node->info & N_SECRET  ) ? " SECRET"  : ""
            );

            printk("XGW: %s: IKEYS PING %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", node->name, _PRINT_KEYS(node->iKeys[I_PAIR_PING]));
            printk("XGW: %s: OKEYS PING %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", node->name, _PRINT_KEYS(node->oKeys[O_PAIR_PING]));

        } break;

        case CMD_PATH_STATUS: {

            printk("XGW: %s [%s]: WEIGHT %u\n",    node->name, path->name, (uint)path->weight);
            printk("XGW: %s [%s]: SINCE %llu\n",   node->name, path->name, (uintll)_PRINT_SINCE(path->since));
            printk("XGW: %s [%s]: STARTS %u\n",    node->name, path->name, (uint)path->starts);
            printk("XGW: %s [%s]: TOS ???\n",      node->name, path->name);
            printk("XGW: %s [%s]: TTL %u\n",       node->name, path->name, (uint)path->ttl);
            printk("XGW: %s [%s]: RTT %ujf\n",     node->name, path->name, (uint)path->rtt);
            printk("XGW: %s [%s]: RTT MIN %ujf\n", node->name, path->name, (uint)path->rtt_min);
            printk("XGW: %s [%s]: RTT MAX %ujf\n", node->name, path->name, (uint)path->rtt_max);
            printk("XGW: %s [%s]: RTT VAR %ujf\n", node->name, path->name, (uint)path->rtt_var);
            printk("XGW: %s [%s]: TIMEOUT %us\n",  node->name, path->name, (uint)path->timeout);

            printk("XGW: %s [%s]: SPORT #%u OF %u\n", node->name, path->name, (uint)path->sPortIndex, (uint)path->sPortsN);
            printk("XGW: %s [%s]: DPORT #%u OF %u\n", node->name, path->name, (uint)path->dPortIndex, (uint)path->dPortsN);

            printk("XGW: %s [%s]: INFO: 0x%02X%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n", node->name, path->name,
           (uint)path->info,
        (path->info & P_ON                  ) ? " ON"             : "",
        (path->info & P_CLIENT              ) ? " CLIENT"         : "",
        (path->info & P_SERVER              ) ? " SERVER"         : "",
        (path->info & P_PHYS                ) ? " PHYS"           : "",
        (path->info & P_MAC_SRC             ) ? " MAC-SRC"        : "",
        (path->info & P_MAC_DST             ) ? " MAC-DST"        : "",
        (path->info & P_ADDR_SRC            ) ? " ADDR-SRC"       : "",
        (path->info & P_ADDR_DST            ) ? " ADDR-DST"       : "",
        (path->info & P_PORT_SRC            ) ? " PORT-SRC"       : "",
        (path->info & P_PORT_DST            ) ? " PORT-DST"       : "",
        (path->info & P_VPROTO              ) ? " VPROTO"         : "",
        (path->info & P_VID                 ) ? " VID"            : "",
        (path->info & P_TOS                 ) ? " TOS"            : "",
        (path->info & P_TTL                 ) ? " TTL"            : "",
        (path->info & P_RTT_MIN             ) ? " RTT-MIN"        : "",
        (path->info & P_RTT_MAX             ) ? " RTT-MAX"        : "",
        (path->info & P_RTT_VAR             ) ? " RTT-VAR"        : "",
        (path->info & P_TIMEOUT             ) ? " TIMEOUT"        : "",
        (path->info & P_NAME                ) ? " NAME"           : "",
        (path->info & P_DHCP                ) ? " DHCP"           : "",
        (path->info & P_DHCP_MAC_DST_SERVER ) ? " MAC-DST-SERVER" : "",
        (path->info & P_DHCP_MAC_DST_GW     ) ? " MAC-DST-GW"     : "",
        (path->info & P_EXIST               ) ? " EXIST"          : "",
        (path->info & K_START               ) ? " START"          : "",
        (path->info & K_SUSPEND             ) ? " SUSPEND"        : "",
        (path->info & K_SUSPENDING          ) ? " SUSPENDING"     : "",
        (path->info & K_LISTEN              ) ? " LISTEN"         : "",
        (path->info & K_ESTABLISHED         ) ? " ESTABLISHED"    : "",
        (path->info & ~P_ALL                ) ? " UNKNOWN"        : ""
            );

            printk("XGW: %s [%s]: LCOUNTER %016llX\n", node->name, path->name, (uintll)path->lcounter);
            printk("XGW: %s [%s]: RCOUNTER %016llX\n", node->name, path->name, (uintll)path->rcounter);

            printk("XGW: %s [%s]: PHYS %s\n", node->name, path->name,
                path->skel.phys ?
                path->skel.phys->name : "-- NULL --"
            );

            printk("XGW: %s [%s]: SKB PROTO 0x%04X\n", node->name, path->name,
                BE16(path->skel.protocol)
            );

            const hdr_eth_s*  const eth  = PKT_ETH  (&path->skel);
            const hdr_vlan_s* const vlan = PKT_VLAN (&path->skel);
            const hdr_ppp_s*  const ppp  = PKT_PPP  (&path->skel);
            const hdr_ip4_s*  const ip4  = PKT_IP4  (&path->skel);
            const hdr_ip6_s*  const ip6  = PKT_IP6  (&path->skel);
            const hdr_udp_s*  const udp  = PKT_UDP  (&path->skel);
            const hdr_tcp_s*  const tcp  = PKT_TCP  (&path->skel);

            if (path_is_eth(path)) {
                printk("XGW: %s [%s]: ETH SRC %02x:%02x:%02x:%02x:%02x:%02x\n", node->name, path->name, MAC(eth->smac));
                printk("XGW: %s [%s]: ETH DST %02x:%02x:%02x:%02x:%02x:%02x\n", node->name, path->name, MAC(eth->dmac));
                printk("XGW: %s [%s]: ETH PROTO 0x%04X\n",                      node->name, path->name, BE16(eth->proto));
            }

            if (path_is_vlan(path)) {
                printk("XGW: %s [%s]: VLAN ID 0x%04X\n",    node->name, path->name, BE16(vlan->id));
                printk("XGW: %s [%s]: VLAN PROTO 0x%04X\n", node->name, path->name, BE16(vlan->proto));
            }

            if (path_is_ppp(path)) {
                printk("XGW: %s [%s]: PPP CODE 0x%04X\n",    node->name, path->name, BE16(ppp->code));
                printk("XGW: %s [%s]: PPP SESSION 0x%04X\n", node->name, path->name, BE16(ppp->session));
                printk("XGW: %s [%s]: PPP SIZE 0x%04X\n",    node->name, path->name, BE16(ppp->size));
                printk("XGW: %s [%s]: PPP PROTO 0x%04X\n",   node->name, path->name, BE16(ppp->proto));
            }

            if (path_is_ip4(path)) {
                printk("XGW: %s [%s]: IP4 TOS 0x%02X\n",      node->name, path->name,  (uint)BE8(ip4->tos));
                printk("XGW: %s [%s]: IP4 TTL %u\n",          node->name, path->name,  (uint)BE8(ip4->ttl));
                printk("XGW: %s [%s]: IP4 PROTO 0x%02X\n",    node->name, path->name,  (uint)BE8(ip4->proto));
                printk("XGW: %s [%s]: IP4 SRC %u.%u.%u.%u\n", node->name, path->name, _PRINT_IP4(ip4->saddr));
                printk("XGW: %s [%s]: IP4 DST %u.%u.%u.%u\n", node->name, path->name, _PRINT_IP4(ip4->daddr));
            }

            if (path_is_ip6(path)) {
                printk("XGW: %s [%s]: IP6 TOS ???\n",                                     node->name, path->name);
                printk("XGW: %s [%s]: IP6 TTL %u\n",                                      node->name, path->name, (uint)BE8(ip6->ttl));
                printk("XGW: %s [%s]: IP6 PROTO 0x%02X\n",                                node->name, path->name, (uint)BE8(ip6->proto));
                printk("XGW: %s [%s]: IP6 SRC %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n", node->name, path->name, _PRINT_IP6(ip6->saddr));
                printk("XGW: %s [%s]: IP6 DST %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n", node->name, path->name, _PRINT_IP6(ip6->daddr));
            }

            if (path_is_udp(path)) {
                printk("XGW: %s [%s]: UDP SRC %u\n", node->name, path->name, (uint)BE16(udp->sport));
                printk("XGW: %s [%s]: UDP DST %u\n", node->name, path->name, (uint)BE16(udp->dport));
            }

            if (path_is_tcp(path)) {
                printk("XGW: %s [%s]: TCP SRC %u\n", node->name, path->name, (uint)BE16(tcp->sport));
                printk("XGW: %s [%s]: TCP DST %u\n", node->name, path->name, (uint)BE16(tcp->dport));
            }

        //u64 acks; // HISTORY
        //u16 ports [PATH_PORTS_N]; // EM BIG ENDIAN

        } break;

        case CMD_PATH_STATS: {

        } break;

        case CMD_NODE_STATS: {

        } break;

        case CMD_NODE_NEW: {

            node_s* const node = paged_alloc(sizeof(node_s));

            if (node == NULL)
                CMD_ERR(ALLOC_NODE);

            // INITIALIZE ZEROED
            memset(node, 0, NODE_SIZE_INIT);

            ASSERT(node->opaths       == 0);
            ASSERT(node->ipaths       == 0);
            ASSERT(node->kpaths       == 0);
            ASSERT(node->conns        == NULL);
            ASSERT(node->connsN       == 0);
            ASSERT(node->info         == 0);
            ASSERT(node->weights      == 0);
            ASSERT(node->mtu          == 0);
            ASSERT(node->lcounter     == 0);
            ASSERT(node->rcounter     == 0);
            ASSERT(node->iCycle       == 0);
            ASSERT(node->oCycle       == 0);
            ASSERT(node->oIndex       == 0);
            ASSERT(node->ptr          == NULL);
            ASSERT(node->next         == NULL);
            ASSERT(node->name[0]      == '\0');
            ASSERT(node->oVersions[0] == 0);
            ASSERT(node->oVersions[1] == 0);
            ASSERT(node->oVersions[2] == 0);
            ASSERT(node->oVersions[3] == 0);
                // node->reserved [2];

            node->nid = nid;
#ifdef CONFIG_XGW_NMAP
            node->gw = nmap[nid];
#endif

            //
            node->oVersions[O_PAIR_PING] = I_PAIR_PING;

            nodes_set_off(nid, node);

        } break;

        case CMD_NODE_ON: {

            //
            if ((node->info & (N_NAME | N_SECRET | N_CONNS_N | N_MTU))
                           != (N_NAME | N_SECRET | N_CONNS_N | N_MTU))
                CMD_ERR(NODE_NOT_CONFIGURED);

            // TODO: NEED AT LEAST ONE PATH?

            // READY TO START
            node->info |= N_ON;
          //node->rDiff    = 0;
            node->lcounter = COUNTER_CONNECTING + 1 + (random64(0) % (0xFFFFFFFFFFFFFFFFULL - COUNTER_CONNECTING - 1 - 512*24*64*64*4));
            node->rcounter = random64(0);

            // WAKE NODE
            __link(node, knodes);

            // BALANCE CONNECTIONS BETWEEN PATHS
            for_count (cid, (uint)node->connsN)
                node->conns[cid] = cid % PATHS_N;

            // NO DYNAMIC KEYS CREATED YET
            { const u64 R = random64(SUFFIX_ULL(CONFIG_XGW_RANDOM_INIT_IPAIRS)); for_count (i, I_PAIRS_DYNAMIC) for_count (k, KEYS_N) node->iKeys[i][k] += R; }
            { const u64 R = random64(SUFFIX_ULL(CONFIG_XGW_RANDOM_INIT_OPAIRS)); for_count (o, O_PAIRS_DYNAMIC) for_count (k, KEYS_N) node->oKeys[o][k] += R; }

            // START ON PATHS
            for_count (pid, PATHS_N) {

                path_s* const path = &node->paths[pid];

                ASSERT(!(path->info & ~P_INFO));

                if (path->info & P_ON) {
                    path->info |= K_START;
                    node->kpaths |= KPATH(pid);
                }
            }

            //
            nodes_set_on(nid, node);

        } break;

        case CMD_NODE_OFF: {

            if (node->info & N_ON) {
                node->info ^= N_ON;

                // STOP ACTIVE PATHS
                for_count (pid, PATHS_N) {

                    path_s* const path = &node->paths[pid];

                    if (path->info & (K_START | K_LISTEN | K_ESTABLISHED))
                        path->info = (path->info & P_INFO) | K_SUSPEND;
                }
            }

        } break;

        case CMD_NODE_SET_SECRET: {

            if (size < PASSWORD_SIZE_MIN
             || size > PASSWORD_SIZE_MAX)
                CMD_ERR(INVALID_PASSWORD_LEN);

            secret_derivate(node, cmd->password, size);

            // TODO: TERA DE FAZER COM TODOS AO MODIFICAR O SELF
            reset_node_ping_keys(node, nodeSelf, nid);

            node->info |= N_SECRET;

        } break;

        case CMD_NODE_SET_CONNS_N: {

            const uint connsN = cmd->connsN;

            if (connsN < CONNS_MIN ||
                connsN > CONNS_MAX)
                CMD_ERR(INVALID_CONNS_N);

            if (connsN != node->connsN) {

                u64* const conns = paged_alloc(CONNS_SIZE(connsN));

                if (conns == NULL)
                    CMD_ERR(ALLOC_CONNS);

                if (node->conns)
                    paged_free(node->conns, CONNS_SIZE(node->connsN));

                node->conns = conns;
                node->connsN = connsN;
                node->info |= N_CONNS_N;
            }

        } break;

        case CMD_PATH_NEW: {

            ASSERT(path->info        == 0);
            ASSERT(path->dhcp        == 0);
            ASSERT(path->weight      == 0);
            ASSERT(path->weight_acks == 0);
            ASSERT(path->since       == 0);
            ASSERT(path->starts      == 0);
            ASSERT(path->timeout     == 0);
            ASSERT(path->reserved32  == 0);
            ASSERT(path->tos         == 0);
            ASSERT(path->ttl         == 0);
            ASSERT(path->rtt         == 0);
            ASSERT(path->rtt_index   == 0);
            ASSERT(path->rtt_min     == 0);
            ASSERT(path->rtt_max     == 0);
            ASSERT(path->rtt_var     == 0);
            ASSERT(path->next        == NULL);
            ASSERT(path->_skb        == NULL);
            ASSERT(path->skel.phys   == NULL);
            ASSERT(path->skel.type   == 0);
            ASSERT(path->sPortsN     == 0);
            ASSERT(path->sPortIndex  == 0);
            ASSERT(path->dPortsN     == 0);
            ASSERT(path->dPortIndex  == 0);
            ASSERT(path->sPorts[0]   == 0);
            ASSERT(path->dPorts[0]   == 0);
            ASSERT(path->rtts[0]     == 0);
            ASSERT(path->name[0]     == 0);

            path->info   = P_EXIST;
            path->nid    = nid;
            path->pid    = pid;
            path->pstats = &node->pstats[pid][0];
         // path->lcounter  -- INITIALIZED NO KEEPER AO DAR START
         // path->rcounter  -- INITIALIZED NO KEEPER AO DAR START
         // path->last      -- INITIALIZED NO KEEPER AO DAR START
         // path->sent      -- INITIALIZED NO KEEPER AO DAR START
         // path->acks      -- INITIALIZED NO KEEPER AO DAR START

        } break;

        case CMD_PATH_SET_PHYS: {
            // TODO: UNREFCOUNT OUR HOOK USAGE VAI SER UM PROBLEMAO POIS OS LISTENINGS PODEM ACABAR DESCOBRINDO ELA :S - basta reverificar se esta hookado ao dar o accept e/ou SUSPEND
            // TODO: HUMMM O ACCEPT NAO DEVE SETAR O P_PHYS

            if (!(phys->flags & IFF_XGW))
                CMD_ERR(PHYS_NOT_HOOKED);

            path->skel.phys = phys;
            path->info |= P_PHYS;

        } break;

        case CMD_PATH_SET_DHCP: {

            // NOTE: SO FAZ SENTIDO SE FOR CLIENTE
            path->dhcp = cmd->did;
            path->info |= P_DHCP;

        } break;

        case CMD_PATH_SET_TYPE: {

            net_device_s* const phys = path->skel.phys;

            const uint type = cmd->type;

            switch (type) {
                case H_TYPE_RAW:
                case H_TYPE_IP4:
                case H_TYPE_IP4_UDP:
                case H_TYPE_IP4_TCP:
                case H_TYPE_IP6:
                case H_TYPE_IP6_UDP:
                case H_TYPE_IP6_TCP:
                case H_TYPE_ETH:
                case H_TYPE_ETH_IP4:
                case H_TYPE_ETH_IP4_UDP:
                case H_TYPE_ETH_IP4_TCP:
                case H_TYPE_ETH_IP6:
                case H_TYPE_ETH_IP6_UDP:
                case H_TYPE_ETH_IP6_TCP:
                case H_TYPE_ETH_VLAN:
                case H_TYPE_ETH_VLAN_IP4:
                case H_TYPE_ETH_VLAN_IP4_UDP:
                case H_TYPE_ETH_VLAN_IP4_TCP:
                case H_TYPE_ETH_VLAN_IP6:
                case H_TYPE_ETH_VLAN_IP6_UDP:
                case H_TYPE_ETH_VLAN_IP6_TCP:
                case H_TYPE_ETH_VLAN_PPP:
                case H_TYPE_ETH_VLAN_PPP_IP4:
                case H_TYPE_ETH_VLAN_PPP_IP6:
                case H_TYPE_ETH_PPP:
                case H_TYPE_ETH_PPP_IP4:
                case H_TYPE_ETH_PPP_IP6:
                    break;
                default:
                    CMD_ERR(INVALID_TYPE);
            }

            memcpy(&path->skel, &models[type], sizeof(pkt_s));

            ASSERT(path->skel.type == type);

            // TODO: ANY OTHER INFO TO RESTORE AFTER ABOVE COPY?
            path->skel.x.src  = BE16(nodeSelf);
            path->skel.x.dst  = BE16(nid);
            path->skel.x.path = BE8(pid);
            path->skel.phys   = phys;

            // SE MUDA O TIPO, PERDE OS OUTROS PARAMETROS
            path->info &= ~__P_TYPE_CLR;

        } break;

        case CMD_PATH_SET_VLAN_PROTO: {

            const uint eProto = cmd->eProto;

            if (eProto != ETH_P_8021Q &&
                eProto != ETH_P_8021AD)
                CMD_ERR(INVALID_VPROTO);

            path->info |= P_VPROTO;

            PKT_ETH(&path->skel)->proto = BE16(eProto);

            path->skel.protocol = BE16(eProto);

        } break;

        case CMD_PATH_SET_VLAN_ID: {

            const uint vid = cmd->vID;

            if (vid > 0x7fff)
                CMD_ERR(INVALID_VID);

            path->info |= P_VID;

            PKT_VLAN(&path->skel)->id = BE16(vid);

        } break;

        case CMD_PATH_SET_ETH_DST: { path->info |= P_MAC_DST; memcpy(PKT_ETH(&path->skel)->dmac, cmd->mac, sizeof(cmd->mac)); } break;
        case CMD_PATH_SET_ETH_SRC: { path->info |= P_MAC_SRC; memcpy(PKT_ETH(&path->skel)->smac, cmd->mac, sizeof(cmd->mac)); } break;

        case CMD_PATH_SET_IP4_SRC: { path->info |= P_ADDR_SRC; memcpy(PKT_IP4(&path->skel)->saddr, cmd->addr4, sizeof(cmd->addr4)); } break;
        case CMD_PATH_SET_IP4_DST: { path->info |= P_ADDR_DST; memcpy(PKT_IP4(&path->skel)->daddr, cmd->addr4, sizeof(cmd->addr4)); } break;
        case CMD_PATH_SET_IP6_SRC: { path->info |= P_ADDR_SRC; memcpy(PKT_IP6(&path->skel)->saddr, cmd->addr6, sizeof(cmd->addr6)); } break;
        case CMD_PATH_SET_IP6_DST: { path->info |= P_ADDR_DST; memcpy(PKT_IP6(&path->skel)->daddr, cmd->addr6, sizeof(cmd->addr6)); } break;

        case CMD_PATH_SET_UDP_SRC:
        case CMD_PATH_SET_TCP_SRC: { path->info |= P_PORT_SRC; path->sPortsN = portsN; memcpy(path->sPorts, cmd->ports, portsN * sizeof(cmd->ports[0])); } break;
        case CMD_PATH_SET_UDP_DST:
        case CMD_PATH_SET_TCP_DST: { path->info |= P_PORT_DST; path->dPortsN = portsN; memcpy(path->dPorts, cmd->ports, portsN * sizeof(cmd->ports[0])); } break;

        case CMD_PATH_SET_WEIGHT_NODE: {

            const uint weight = cmd->weight_node;

            if (weight > PATH_WEIGHT_MAX)
                CMD_ERR(INVALID_WEIGHT);

            node->weights -= path->weight;
            node->weights += weight;
            path->weight   = weight;

        } break;

        case CMD_PATH_SET_WEIGHT_ACKS: {

            const uint wacks = cmd->weight_acks;

            if (wacks == 0
             || wacks > ACKS_N)
                CMD_ERR(INVALID_WEIGHT);

            path->weight_acks = wacks;

        } break;

        case CMD_PATH_SET_CLIENT: path->info = (path->info & ~P_SERVER) | P_CLIENT; break;
        case CMD_PATH_SET_SERVER: path->info = (path->info & ~P_CLIENT) | P_SERVER; break;

        case CMD_PATH_SET_TIMEOUT: {

            const uint timeout = cmd->timeout;

            if (timeout < PATH_TIMEOUT_MIN
             || timeout > PATH_TIMEOUT_MAX)
                CMD_ERR(INVALID_TIMEOUT);

            path->timeout = timeout;
            path->info |= P_TIMEOUT;

        } break;

        case CMD_PATH_SET_RTT_MIN: { // TODO: ARREDONDAR PARA CIMA?

            const uintll rtt = ((uintll)cmd->rtt * HZ) / 1000;

            if (rtt < PATH_RTT_MIN
             || rtt > PATH_RTT_MAX)
                CMD_ERR(INVALID_RTT);

            path->rtt_min = rtt;
            path->info |= P_RTT_MIN;

        } break;

        case CMD_PATH_SET_RTT_MAX: { // TODO: ARREDONDAR PARA CIMA?

            const uintll rtt = ((uintll)cmd->rtt * HZ) / 1000;

            if (rtt < PATH_RTT_MIN
             || rtt > PATH_RTT_MAX)
                CMD_ERR(INVALID_RTT);

            path->rtt_max = rtt;
            path->info |= P_RTT_MAX;

        } break;

        case CMD_PATH_SET_RTT_VAR: { // TODO: ARREDONDAR PARA CIMA?

            const uintll rtt = ((uintll)cmd->rtt * HZ) / 1000;

            if (rtt < PATH_RTT_VAR_MIN
             || rtt > PATH_RTT_VAR_MAX)
                CMD_ERR(INVALID_RTT);

            path->rtt_var = rtt;
            path->info |= P_RTT_VAR;

        } break;

        case CMD_NODE_SET_MTU: {

            const uint mtu = cmd->mtu;

            if (mtu < MTU_MIN ||
                mtu > MTU_MAX)
                CMD_ERR(INVALID_MTU);

            node->mtu = mtu;
            node->info |= N_MTU;

        } break;

        case CMD_NODE_SET_NAME: {

            if (!cmd->nname[0] ||
                 cmd->nname[NODE_NAME_SIZE - 1])
                CMD_ERR(INVALID_NODE_NAME);

            memset(node->name, 0, sizeof(node->name));
            strcpy(node->name, cmd->nname);

            node->info |= N_NAME;

        } break;

        case CMD_PATH_SET_NAME: {

            if (!cmd->pname[0] ||
                 cmd->pname[PATH_NAME_SIZE - 1])
                CMD_ERR(INVALID_PATH_NAME);

            memset(path->name, 0, sizeof(path->name));
            strcpy(path->name, cmd->pname);

            path->info |= P_NAME;

        } break;

        case CMD_PATH_SET_IP_TTL:
        case CMD_PATH_SET_IP4_TTL:
        case CMD_PATH_SET_IP6_TTL: {

            const uint ttl = cmd->ttl;

            if (ttl < TTL_MIN ||
                ttl > TTL_MAX)
                CMD_ERR(INVALID_TTL);

            path->ttl = ttl;
            path->info |= P_TTL;

        } break;

        case CMD_PATH_SET_IP_TOS:
        case CMD_PATH_SET_IP4_TOS:
        case CMD_PATH_SET_IP6_TOS: {

            const uint tos = cmd->tos;

            if (tos > TOS_MAX)
                CMD_ERR(INVALID_TOS);

            path->tos = tos;
            path->info |= P_TOS;

        } break;

        case CMD_PATH_SET_PPP_SESSION: {

            const uint session = cmd->session;

            if (session > 0xFFFF)
                CMD_ERR(INVALID_SESSION);

            switch (path->skel.type) {
                case H_TYPE_ETH_PPP:
                case H_TYPE_ETH_VLAN_PPP:
                    path->skel.encap_eth_ppp.ppp.session = BE16(session);
                    break;
                case H_TYPE_ETH_PPP_IP4:
                case H_TYPE_ETH_VLAN_PPP_IP4:
                    path->skel.encap_eth_ppp_ip4.ppp.session = BE16(session);
                    break;
                case H_TYPE_ETH_PPP_IP6:
                case H_TYPE_ETH_VLAN_PPP_IP6:
                    path->skel.encap_eth_ppp_ip6.ppp.session = BE16(session);
                    break;
            }

            // path->info |= P_SESSION; TODO:

        } break;

        // TODO: RANDOMIZE NODE SECRET ON CLEAR

        case CMD_NODE_CLR_NAME: node->info &= ~N_NAME; *node->name = '\0'; break;
        case CMD_PATH_CLR_NAME: path->info &= ~P_NAME; *path->name = '\0'; break;

        case CMD_NODE_CLR_SECRET: node->info &= ~N_SECRET; break;

        case CMD_PATH_CLR_PHYS:       path->info &= ~P_PHYS;      break;
        case CMD_PATH_CLR_ETH_DST:    path->info &= ~P_MAC_DST;   break;
        case CMD_PATH_CLR_ETH_SRC:    path->info &= ~P_MAC_SRC;   break;
        case CMD_PATH_CLR_VLAN_PROTO: path->info &= ~P_VPROTO;    break;
        case CMD_PATH_CLR_VLAN_ID:    path->info &= ~P_VID;       break;
        case CMD_PATH_CLR_IP4_TOS:
        case CMD_PATH_CLR_IP6_TOS:    path->info &= ~P_TOS;       break;
        case CMD_PATH_CLR_IP4_TTL:
        case CMD_PATH_CLR_IP6_TTL:    path->info &= ~P_TTL;       break;
        case CMD_PATH_CLR_IP4_SRC:
        case CMD_PATH_CLR_IP6_SRC:    path->info &= ~P_ADDR_SRC;  break;
        case CMD_PATH_CLR_IP4_DST:
        case CMD_PATH_CLR_IP6_DST:    path->info &= ~P_ADDR_DST;  break;
        case CMD_PATH_CLR_UDP_SRC:
        case CMD_PATH_CLR_TCP_SRC:    path->info &= ~P_PORT_SRC;  break;
        case CMD_PATH_CLR_UDP_DST:
        case CMD_PATH_CLR_TCP_DST:    path->info &= ~P_PORT_DST;  break;
        case CMD_PATH_CLR_DHCP:       path->info &= ~P_DHCP;      break;
        case CMD_PATH_CLR_TYPE:       path->info &= ~__P_TYPE_CLR; break;

        case CMD_NODE_DEL: {

#ifdef CONFIG_XGW_NMAP
            __atomic_store_n(&nmap[node->nid], node->gw, __ATOMIC_SEQ_CST);
#endif

            // FREE CONNS
            if (node->conns)
                paged_free(node->conns, CONNS_SIZE(node->connsN));

            // CLEAR SECRETS FROM MEMORY
            memset(node, 0, sizeof(node_s));

            // FREE NODE
            paged_free(node, sizeof(node_s));

            nodes_set_on(nid, NULL);

        } break;

        case CMD_STATS: {

            stats_print();

        } break;

#ifdef CONFIG_XGW_NMAP
        case CMD_NMAP: {

            const uint gw = cmd->nid2;

            if (gw >= NODES_N)
                CMD_ERR(INVALID_NID);

            node = (node_s*)((uintptr_t)nodes[nid] & ~(uintptr_t)1);

            if (node)
                node->gw = gw;

            // NOTE: NAO CHECA POR N_ON, POIS SE TIVER OPATHS, ENTAO ESTA ON
            if (!(node && node->opaths))
                __atomic_store_n(&nmap[nid], gw, __ATOMIC_SEQ_CST);

        } break;
#endif

        default:
        // TODO: NESTE CASO, ERRO NÃO SUPPORTADO
         _CMD_ERR(INVALID_PATH_NAME);
    }

failed:

    //
    if (phys)
        dev_put(phys);

    // UNLOCK
    spin_unlock_irqrestore(&xlock, iflags);

failed_free:
    kfree(buff);

failed_nothing:

    return e;
}
