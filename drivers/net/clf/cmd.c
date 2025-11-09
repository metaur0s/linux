
static ssize_t __cold_as_ice __optimize_size cmd (struct file *file, const char __user *ubuf, size_t size, loff_t *ppos) {

    cmd_s cmd;

    //
    if (size != sizeof(cmd_s))
        return -ESIZE;
    
    if (copy_from_user(&cmd, ubuf, size))
        return -EINVAL;

    net_device_s* phys = NULL;
    
    const uint code = cmd->code;
    const uint pid  = cmd->pid;

    // VALIDATE COMMAND
    if (code >= CMDS_N)
        return -EINVAL;
    
    // VALIDATE PATH
    if (pid >= PATHS_N)
        return -EINVAL;

    switch (code) {
        case CMD_PATH_PHYS_SET:
            // MUST HAVE A VALID NAME
            if (!cmd->phys[0] ||
                 cmd->phys[IFNAMSIZ - 1])
                return -EINVAL;
            // LOOKUP IT, OWNED
            phys = dev_get_by_name(&init_net, cmd->phys);
            // MUST EXIST
            if (phys == NULL)
                return -ENODEV;
            // CANNOT BE THE VPN ITSELF
            if (phys == clf)
                return -EINVAL;
    }
    
    // LOCK CLF
    unsigned long iflags;

    spin_lock_irqsave(&xlock, iflags);

    path_s* const path = &paths[pid];

    switch (code) {

        case CMD_PATH_ON:

            printk("CLF: PATH %u: ON\n", pid);

            __atomic_store_n(&opaths, opaths | (0x00010001U << pid), __ATOMIC_SEQ_CST);

            break;

        case CMD_PATH_OFF:

            printk("CLF: PATH %u: OFF\n", pid);

            __atomic_store_n(&opaths, opaths & ~(0x00010001U << pid), __ATOMIC_SEQ_CST);

            break;

        case CMD_PATH_PHYS_SET:

            ASSERT(phys != NULL);

            printk("CLF: PATH %u: PHYS %s\n", phys->name);
			
            // USE IT
            phys = __atomic_exchange_n(&path->phys, phys, __ATOMIC_SEQ_CST);

            // WILL REMEMBER THE NEW
            // WILL RELEASE THE OLD

            break;

        case CMD_PATH_PHYS_CLR:

            printk("CLF: PATH %u: PHYS CLEAR\n", pid);

            ASSERT(phys == NULL);

            //
            __atomic_store_n(&opaths, opaths & ~(0x00010001U << pid), __ATOMIC_SEQ_CST);

            //
            phys = __atomic_exchange_n(&path->phys, NULL, __ATOMIC_SEQ_CST);

            // WILL RELEASE THE OLD

            break;

        case CMD_PATH_PRINT:

            printk("CLF: PATH %u ENABLED %d\n", pid, !!(opaths & (1U << pid)));
            printk("CLF: PATH %u PHYS %s\n",               pid, path->phys ? path->phys->name : "");
            printk("CLF: PATH %u SKB MAC LEN %u\n",        pid, (uint)path->mac_len);
            printk("CLF: PATH %u SKB PROTOCOL 0x%04X\n",   pid, (uint)path->protocol);
            printk("CLF: PATH %u SKB ENCAP TYPE %u\n",     pid, (uint)path->eType);
            printk("CLF: PATH %u SKB ENCAP SIZE %u\n",     pid, (uint)path->eSize);
            printk("CLF: PATH %u SKB ENCAP E OFFSET %u\n", pid, (uint)path->eOffset);
            printk("CLF: PATH %u SKB ENCAP N OFFSET %u\n", pid, (uint)path->nOffset);

            break;

        case CMD_PATH_ENCAP_RAW:

            memset(&path->encap, 0, ENCAP_SIZE);

            path->eType    = ENCAP_TYPE_RAW;
            path->eSize    = ENCAP_SIZE_RAW;
            path->eOffset  = ENCAP_OFFSET_RAW;
            path->nOffset  = ENCAP_SIZE_RAW;
            path->pWord    = 0;
            path->protocol = BE16(ETH_P_IP);
            path->mac_len  = 0;

            break;

        case CMD_PATH_ENCAP_ETH:

            memcpy(&path->encap, &cmd->encap, ENCAP_SIZE);

            path->eType    = ENCAP_TYPE_ETH;
            path->eSize    = ENCAP_SIZE_ETH;
            path->eOffset  = ENCAP_OFFSET_ETH;
            path->nOffset  = ENCAP_SIZE_ETH;
            path->pWord    = 0;
            path->protocol = BE16(ETH_P_IP);
            path->mac_len  = ETH_HLEN;
            path->encap.eth.eProto = BE16(ETH_P_IP);

            break;

        case CMD_PATH_ENCAP_ETH_VLAN:

            memcpy(&path->encap, &cmd->encap, ENCAP_SIZE);

            path->eType    = ENCAP_TYPE_ETH_VLAN;
            path->eSize    = ENCAP_SIZE_ETH_VLAN;
            path->eOffset  = ENCAP_OFFSET_ETH_VLAN;
            path->nOffset  = ENCAP_OFFSET_ETH_VLAN + ETH_HLEN;
            path->pWord    = 0;
            path->protocol = BE16(ETH_P_8021Q);
            path->mac_len  = ETH_HLEN;
            path->encap.eth_vlan.eProto = BE16(ETH_P_8021Q);
            path->encap.eth_vlan.vProto = BE16(ETH_P_IP);

            break;

        case CMD_PATH_ENCAP_ETH_VLAN_PPP:

            memcpy(&path->encap, &cmd->encap, ENCAP_SIZE);

            path->eType    = ENCAP_TYPE_ETH_VLAN_PPP;
            path->eSize    = ENCAP_SIZE_ETH_VLAN_PPP;
            path->eOffset  = ENCAP_OFFSET_ETH_VLAN_PPP;
            path->nOffset  = ENCAP_OFFSET_ETH_VLAN_PPP + ETH_HLEN;
            path->pWord    = offsetof(encap_eth_vlan_ppp_s, pSize) / sizeof(u16);
            path->protocol = BE16(ETH_P_8021Q);
            path->mac_len  = ETH_HLEN;
            path->encap.eth_vlan_ppp.eProto = BE16(ETH_P_8021Q);
            path->encap.eth_vlan_ppp.vProto = BE16(ETH_P_PPP_SES);
            path->encap.eth_vlan_ppp.pProto = BE16(0x0021);

            break;

        case CMD_PATH_ENCAP_ETH_PPP:

            memcpy(&path->encap, &cmd->encap, ENCAP_SIZE);

            path->eType    = ENCAP_TYPE_ETH_PPP;
            path->eSize    = ENCAP_SIZE_ETH_PPP;
            path->eOffset  = ENCAP_OFFSET_ETH_PPP;
            path->nOffset  = ENCAP_OFFSET_ETH_PPP + ETH_HLEN;
            path->pWord    = offsetof(encap_eth_ppp_s, pSize) / sizeof(u16);
            path->protocol = BE16(ETH_P_PPP_SES);
            path->mac_len  = ETH_HLEN;
            path->encap.eth_ppp.eProto = BE16(ETH_P_PPP_SES);
            path->encap.eth_ppp.pProto = BE16(0x0021);

            break;

        case CMD_PATH_ENCAP_ETH_VLAN_PPP_SESSION:

            ASSERT(path->eType == ENCAP_TYPE_ETH_VLAN_PPP);

            const uint session = cmd->encap.eth_vlan_ppp.pSession;
                                path->encap.eth_vlan_ppp.pSession = BE16(session);

            printk("CLF: PATH %u: PPP SESSION SET TO 0x%04X\n", pid, session);

            break;

        case CMD_PATH_ENCAP_ETH_PPP_SESSION:

            ASSERT(path->eType == ENCAP_TYPE_ETH_PPP);

            const uint session = cmd->encap.eth_ppp.pSession;
                                path->encap.eth_ppp.pSession = BE16(session);

            printk("CLF: PATH %u: PPP SESSION SET TO 0x%04X\n", pid, session);
            
            break;
    }

    // FORGET THE PHYSICAL DEVICE
    if (phys)
        dev_put(phys);

    // UNLOCK CLF
    spin_unlock_irqrestore(&xlock, iflags);

    return sizeof(cmd_s);
}
