
#define __ct1(x) __ctz(~(x))

static void keeper (struct timer_list* const timer) {

#ifdef CONFIG_XGW_BEEP
    uint beep = 0; // O OBJETIVO É BEEPAR CONFORME A SITUAÇÃO DO PIOR node
    // CONFORME OS NODES
#endif

    // LOCK
    unsigned long iflags;

    spin_lock_irqsave(&xlock, iflags);

    //const uint up = !!(xgw->flags & IFF_UP); // == N_ON & P_ON

    timer->expires = jiffies + KEEPER_INTERVAL;

    const u64 now = get_jiffies_64();

    for (node_s* node = knodes; node; node = node->next) {

        ASSERT(!node_is_off(node));

        ASSERT(*node->ptr == node);

        // PARAMETERS
        ASSERT(node->info & N_CONNS_N);
        ASSERT(node->info & N_MTU);
        ASSERT(node->info & N_NAME);

        ASSERT(node->mtu >= MTU_MIN);
        ASSERT(node->mtu <= MTU_MAX);

        ASSERT(node->connsN >= CONNS_MIN);
        ASSERT(node->connsN <= CONNS_MAX);

        ASSERT((node->info   & N_INFO) == node->info);
        ASSERT((node->opaths & OPATHS) == node->opaths);
        ASSERT((node->ipaths & IPATHS) == node->ipaths);
        ASSERT((node->kpaths & KPATHS) == node->kpaths);

        ASSERT((node->opaths & (node->kpaths * OPATH_0)) == node->opaths);
        ASSERT((node->ipaths & (node->kpaths * IPATH_0)) == node->ipaths);

        ASSERT(node->oVersions[O_PAIR_PING] == I_PAIR_PING);

        __atomic_add_fetch(&node->rcounter, 1, __ATOMIC_SEQ_CST); // O OUT USA ISSO PARA ENVIAR
        __atomic_add_fetch(&node->lcounter, 1, __ATOMIC_SEQ_CST); // O IN USA ISSO PARA RECEBER

#ifdef CONFIG_XGW_BEEP // SITUACAO DESTE NODE, CONFORME OS PATHS
        uint stableWeights = 0, stableSum = 0;
#endif

        // BUILD
        u64 opaths = 0;

        // ITERATE
        uint kpaths = node->kpaths;

        while (kpaths) { const uint pid = __ctz(kpaths); kpaths ^= KPATH(pid);

            path_s* const path = &node->paths[pid];

            ASSERT(path->nid == node->nid);
            ASSERT(path->pid == pid);

            if (path->info & K_START) { //231956

                if (path->info & P_CLIENT) {

                    if (path->info & P_DHCP) {
#if 0
                        if (1) {
                          // DHCP IS DONE
                          if (path_is_ip4(path)) {
                              ASSERT(dhcp->type == ipv4);
                              // copy ipv4 address to src
                          } elif (path_is_ip6(path)) {
                              ASSERT(dhcp->type == ipv6);
                              // copy ipv6 address to src
                          }
                          // copy phys
                          // copy smac
                          // copy dmac
                          // copy eth protocol
                          // copy vlan id
                        } else
#endif
                            // CANNOT START YET
                            goto _skip;
                    }

                    printk("XGW: %s [%s]: CONNECTING\n", node->name, path->name);

                    // THE TTL AND TOS ARE STORED OUTSIDE THE SKEL, OTHERWISE WE LOSE THEM ON EVERY IN-DISCOVER.
                    // SO, THE CMD ALSO STORED THEM DIRECTLY ON PATH.
                    // HERE WE COPY THEM TO THE SKEL
                    if (path_is_ip4(path)) { hdr_ip4_s* const ip4 = PKT_IP4(&path->skel);
                        ip4->tos = BE8(path->tos);
                        ip4->ttl = BE8(path->ttl);
                    } elif (path_is_ip6(path)) { hdr_ip6_s* const ip6 = PKT_IP6(&path->skel);
                        ip6->tos = BE8(path->tos);
                        ip6->ttl = BE8(path->ttl);
                        ip6->flow = BE16(0x1111U * path->pid);
                    }

                    // TODO: PRECOMPUTE TCP CHECKSUM
                    // TODO: PRECOMPUTE UDP CHECKSUM (FOR IPV6)
                    if (path_is_udp_tcp(path)) { // TODO: ALTERNAR TAMBEM O DPORT
                        path->sPortIndex += 1;
                        path->sPortIndex %= path->sPortsN;
                        path->dPortIndex += path->sPortIndex == 0;
                        path->dPortIndex %= path->dPortsN;
                        // BOTH UDP AND TCP PORTS START ON TRANSPORT
                        hdr_udp_s* const udp = PKT_UDP(&path->skel);
                        udp->sport = BE16(path->sPorts[path->sPortIndex]);
                        udp->dport = BE16(path->dPorts[path->dPortIndex]);
                    }

                    // TODO: FAZER ISSO A TODOS OS NODES-PATHS AO SETAR O SELF
                    // TODO: TEM QUE REPENSAR O CRYPTO DERIVATE, POIS SENAO SE MUDAR O SELF, TERA DE SETAR NOVAMENTE O SECRET
                    path->skel.x.src  = BE16(nodeSelf);

                    path->rcounter   = COUNTER_CONNECTING;
                } else {
                    printk("XGW: %s [%s]: LISTENING\n", node->name, path->name);
                    path->skel.type  = 0; //
                    path->rcounter   = COUNTER_LISTENING;
                }   path->lcounter   = 0; // AINDA NAO RECEBI PONG
                    path->sent       = 0; // AINDA NAO CONSTRUI PING
                    path->since      = 0; // AINDA NAO RECEBI O PRIMEIRO [MEU COUNTER]
                    path->info      ^= K_START | K_LISTEN;

                // ENABLE IN
                // NOTE: AQUI ENTAO TEM UM RACE CONDITION, ELE PODE RECEBER UM PING/PONG E COMO SERÁ INTERPRETADO?
                __atomic_store_n(&node->ipaths, node->ipaths | IPATH(pid), __ATOMIC_SEQ_CST);
            }

            if (path->info & K_LISTEN) {

                if (__atomic_load_n(&path->rcounter, __ATOMIC_SEQ_CST) >= COUNTER_CONNECTING) {

                    if (path->info & P_SERVER)
                        printk("XGW: %s [%s]: ACCEPTED ON PHYS %s\n", node->name, path->name, path->skel.phys->name);

                    // AT THIS POINT, THE PATH->SKEL WAS BUILT
                    //      a) FROM USER (CMD)
                    //      b) FROM IN (DISCOVER)

                    // O DISCOVER TEM QUE TER FEITO ISSO
                    // O USERSPACE TEM QUE TER FEITO ISSO
                    ASSERT(path->skel.x.src  == BE16(nodeSelf));
                    ASSERT(path->skel.x.dst  == BE16(path->nid));
                    ASSERT(path->skel.x.path == BE8 (path->pid));
                        // path->skel.x.version --> ON encrypt()
                        // path->skel.x.dsize   --> ON encrypt()
                        // path->skel.x.seed    --> ON encrypt()
                        // path->skel.x.hash    --> ON encrypt()

                    path->info      ^= K_LISTEN | K_ESTABLISHED;
                    path->acks       = 0;
                    path->since      = now;
                    path->last       = now;
                    path->starts    += 1;
                    path->rtt        = path->rtt_max + path->rtt_var;
                    path->rtt_index  = 0;
                 // path->sent      -> 0  --- SERA SETADO ABAIXO
                 // path->lcounter  -> 0  --- SERA SETADO ABAIXO
                 // path->rcounter  -> a) COUNTER_CONNECTING (KEEPER - START)
                 //                    b) COUNTER DO PEER (IN - PING)

                    for_count (i, PATH_RTTS_N)
                        path->rtts[i] = path->rtt;

                    // QUANDO FIZER PINGS, VAI MANDAR
                    const uint q = path->skel.phys->ifindex % PING_QUEUES_N;

                    path->next = pings[q];
                                 pings[q] = path;
                }
            }

            if (path->info & K_ESTABLISHED) {

                if (!(path->skel.phys->flags & IFF_UP)) {
                    printk("XGW: %s [%s]: PHYS %s IS DOWN\n", node->name, path->name, path->skel.phys->name);
                    goto _suspend;
                }

                // PEGA O TIME DE QUANDO ELE RECEBEU UM PONG
                // ESTE TIME SÓ É ESCRITO SE O MEU COUNTER, CITADO NO PONG, É O QUE ESTÁ NELE
                //      cmp_exchange(path->lcounter, pong_lcounter, get_jiffies64())
                // O UNICO QUE ESCREVE EM PATH->LCOUNTER
                //      a) AQUI, QUANDO PASSO A CONSIDERAR O NOVO NODE->COUNTER
                //      b) IN_PONG, AO SUBSTITUIR ESTE VALOR DE NODE->COUNTER --> NOW
                // ENTAO ESTE PATH->LCOUNTER LIDO SO PODE SER:
                //      a) O NODE->LCOUNTER COLOCADO ANTERIORMENTE, AQUI (node->lcounter - 1)
                //      b) O TIME COLOCADO PELO IN_PONG
                //      c) O 0 INICIAL
                const u64 received = __atomic_exchange_n(&path->lcounter, node->lcounter, __ATOMIC_SEQ_CST);

                if (received) {

                    if (received != (node->lcounter - 1)) {
                        // RECEBEU

                        // ELAPSED TIME: PONG_RECEIVED - PING_SENT
                        u64 rtt = received - path->sent;

                        // FORCE CONFIGURED LIMITS
                        if   (rtt < path->rtt_min)
                              rtt = path->rtt_min;
                        elif (rtt > path->rtt_max)
                              rtt = path->rtt_max;

                        // REPLACE THE OLDEST WITH IT
                        path->rtts[path->rtt_index++ % PATH_RTTS_N] = rtt;

                        // CALCULATE THE AVERAGE, WEIGHTING THE HIGHESTS
                        // REFORCA ESTE NOVO
                        u64 w = rtt; rtt *= rtt;

                        for_count (i, PATH_RTTS_N) {
                            const u64 x = path->rtts[i];
                            w   += x;
                            rtt += x * x;
                        }

                        rtt /= w;

                        // ATURA VARIACOES
                        rtt += path->rtt_var;

                        // TODO: USE IT ON THE CONNECTIONS
                        __atomic_store_n(&path->rtt, rtt, __ATOMIC_RELAXED);

                        // USE O NOW AO INVES DE RECEIVED POIS O RECEIVED PODE ESTAR ERRADO (SER UM COUNTER)
                        path->last = now;

                    } elif ((path->last + path->timeout * HZ) < now) {
                        // NOT RECEIVED, AND TIMED OUT
                        printk("XGW: %s [%s]: TIMED OUT\n", node->name, path->name);
                        goto _suspend;
                    }

                    // A SECOND ELAPSED
                    // TODO: ELE TEM QUE TER RECEBIDO TAMBEM UM PING, HA PELO MENOS 2 KEEPER INTERVALS
                    // TODO: E A INTERFACE ESTA UP
                    // TODO: E A INTERFACE ESTA COM CARRIER
                    const u64 acks = (path->acks << 1) | (received <= (path->sent + path->rtt));

                    if (path->acks != acks) {
                        path->acks = acks;
                        // CHANGED

                        const char* str;

                        switch (acks) {
                            case 0x0000000000000000ULL: str = "LOST";       break;
                            case 0x0000000000000001ULL: str = "RECOVERING"; break;
                            case 0xFFFFFFFFFFFFFFFEULL: str = "UNSTABLE";   break;
                            case 0xFFFFFFFFFFFFFFFFULL: str = "STABLE";     break;
                            default:                    str = NULL;
                        }

                        if (str)
                            printk("XGW: %s [%s]: %s WITH RTT %u\n", node->name, path->name, str, (uint)path->rtt);
                    }

                    // DOS PIORES AOS MELHORES
                #define IS_STABLE(acks, interval, loss) (popcount((acks) << (ACKS_N - (interval))) >= ((interval) - (loss)))
                    opaths |= (
                        (((u64)IS_STABLE(acks, 12, 8)) << (3*PATHS_N)) | // BASTA QUE ESTEJA FUNCIONANDO ENTAO
                        (((u64)IS_STABLE(acks, 20, 1)) << (2*PATHS_N)) |
                        (((u64)IS_STABLE(acks, 12, 0)) << (1*PATHS_N)) | // NOTE: THIS ONE SHOULD BE REPEATED
                         ((u64)IS_STABLE(acks, 12, 0)) // TODO: REMOVE THIS REPETITION LIMITATION
                    ) << pid;
                }

                // MAKE PING
                // TODO: SO FAZER ISSO SE A INTERFACE ESTIVER UP E COM CARRIER, PARA NAO PERDER IKEYS ATOA
                // NOTE: RESERVA HEAD AND TAIL ROOM POIS PODE TER MAIS ENCAPSULAMENTOS NO PHYS
                skb_s* const skb = alloc_skb(64 + sizeof(pkt_s) + sizeof(u64) + PING_SIZE + 64, GFP_ATOMIC);

                if ((path->_skb = skb)) {

                    // TODO: AQUI PELO MENOS PODEMOS ALINHAR - PTR(((uintptr_t)SKB_DATA(skb) + sizeof(u64) - 1) % sizeof(u64))
                    u64* const ping = SKB_DATA(skb) + 64 + sizeof(pkt_s) + sizeof(u64);

                    // A CADA PING A INPUT KEY MAIS ANTIGA É EXPIRADA
                    const uint i = node->iCycle = ((uint)node->iCycle + 1) % I_PAIRS_DYNAMIC;

                    for_count (i, PING_WORDS_N) {
                        ping[i] += random64(SUFFIX_ULL(CONFIG_XGW_RANDOM_PING));
                    }   ping[P__CTR]  = BE64(node->lcounter);
                        ping[P__VER] &= BE64(0xFFFFFFFFFFFFFF00ULL);
                        ping[P__VER] |= BE64(i);

                    // SEM ATOMICITY/BARRIER POR QUE O PEER SO VAI REFERENCIAR ESSE NOSSO INPUT INDEX QUANDO ELE RECEBER
                    learn(node, ping, node->iKeys[i]);

                    // BUILD THE PING FROM THE SKEL
                    pkt_encapsulate(node, O_PAIR_PING, // ELE VAI MANDAR SYN ATÉ RECEBER O PRIMEIRO PING, O QUAL MARCARA O RCOUNTER
                        __atomic_load_n(&path->rcounter, __ATOMIC_RELAXED) == COUNTER_CONNECTING ? COUNTER_SYN :
                        __atomic_load_n(&node->rcounter, __ATOMIC_RELAXED), // TODO: SO PODE MARCAR O path->rcounter *APOS* ATUALIZAR O node->rcounter
                        &path->skel, skb, ping, PING_SIZE
                    );
                }
            }

            if (path->info & K_SUSPEND) { // NOTE: WILL EXECUTE TWICE BECAUSE THE ATOMIC EXCHANTE BELOW
                // STOP PING (BY REMOVING K_ESTABLISHED)
                // STOP OUT (BY NOT INCLUDING IN OPATHS)
                // STOP IN
_suspend:
                path->info = (path->info & P_INFO) | K_SUSPENDING;
                path->acks = 0; // PARA JA ATUALIZAR O BEEP

                __atomic_store_n(&node->ipaths, node->ipaths & ~IPATH(pid), __ATOMIC_RELAXED);
                // NOW ANOTHER INTERVAL SO ANY IN/OUT IS DONE
            } elif (path->info & K_SUSPENDING) { BUILD_ASSERT(N_ON == P_ON);
                if ((path->info ^= K_SUSPENDING) & node->info & N_ON & P_ON) {
                     path->info |= K_START;
                } else {
                    printk("XGW: %s [%s]: STOPPED\n", node->name, path->name);
                    // NOW THE PATH IS STOPPED
                    // NOTE: THE PATH MAY BE ON, FOR EXAMPLE IF THE PATH STOPPED BECAUSE THE NODE STOPED
                    node->kpaths ^= KPATH(pid);
                }
            }

_skip:
#ifdef CONFIG_XGW_BEEP
            // NOTE: TEM QUE FAZER ISSO ENQUANTO O NODE E O PATH ESTIVEREM ATIVADOS
            // TODO: MULTIPLICAR POR UM FATOR PARA NAO DEIXAR FICAR UM VALOR PEQUENO, JA QUE NAO PODE USAR FLOAT
            // ASSIM MELHORARA A PRECISAO DO RESULTADO
            if ((uint)(node->info & path->info & N_ON & P_ON) * path->weight * path->weight_acks) {
                stableWeights += (1024 * path->weight);
                stableSum += (popcount(path->acks & ((1ULL << path->weight_acks) - 1)) * (1024 * path->weight)) / path->weight_acks;
            }
#endif
        }

        if (node->info & N_ON) {
            // SALVA
            if (node->opaths != opaths) {
#ifdef CONFIG_XGW_NMAP
                if (!opaths)
                    // O NODE AGORA VAI FICAR SEM PATHS FUNCIONANDO; PASSA A USAR O GW
                    __atomic_store_n(&nmap[node->nid], node->gw, __ATOMIC_SEQ_CST);
                elif (!node->opaths)
                    // O NODE NÃO TINHA PATHS FUNCIONANDO E AGORA TEM; DEIXA DE USAR O GW
                    __atomic_store_n(&nmap[node->nid], node->nid, __ATOMIC_SEQ_CST);
#endif
                __atomic_store_n(&node->opaths, opaths, __ATOMIC_SEQ_CST);
            }
#ifdef CONFIG_XGW_BEEP
            if (node->weights) {
                // (0 ... 1) * BEEP MAX
                const uint q = CONFIG_XGW_BEEP_BASE + (((node->weights - wstable) * (CONFIG_XGW_BEEP_MAX - CONFIG_XGW_BEEP_BASE)) / node->weights);
                if (beep > q)
                    beep = q;
            }
#endif
        } elif (nodes[node->nid] == node) {
            // VAI FORCAR UM INTERVALO SEM O IN/OUT ACESSAR O NODE
            // ALSO NEEDS A BREAK TIME FOR CHANGING COUNTERS

#ifdef CONFIG_XGW_NMAP
            // O NODE AGORA VAI FICAR OFF; PASSA A USAR O GW
            __atomic_store_n(&nmap[node->nid], node->gw, __ATOMIC_SEQ_CST);
#endif
            __atomic_store_n(&node->opaths, 0, __ATOMIC_SEQ_CST);

            ASSERT(!opaths);
            
            ASSERT(!node->opaths);
            ASSERT(!node->ipaths);

            nodes_set_off(node->nid, node);

        } elif (!node->kpaths) {

            ASSERT(!opaths);

            ASSERT(!node->opaths);
            ASSERT(!node->ipaths);

            __unlink(node);

            printk("XGW: %s: STOPPED\n", node->name);
        }

#ifdef CONFIG_XGW_BEEP // SITUACAO DESTE NODE, CONFORME OS PATHS
        if (node->info & N_ON) {
            stableSum /= stableWeights;
            if (beep < stableSum)
                beep = stableSum;
        }
#endif
    }

    spin_unlock_irqrestore(&xlock, iflags);

    // SEND PINGS
    for_count (q, PING_QUEUES_N) {

        path_s** ptr = &pings[q]; path_s* path;

        while ((path = *ptr)) {
            if (path->info & K_ESTABLISHED) {
                //

                skb_s* const skb = path->_skb; uint len; uint s;

                if (skb) {
                    path->_skb = NULL;
                    path->sent = get_jiffies_64();

                    // TEM QUE LER ANTES POIS O SKB SERA PERTIDO
                    len = skb->len;

                    skb->ip_summed = CHECKSUM_NONE;
                    if (dev_queue_xmit(skb)) // TODO: SAME ON DEV_OUT(), BUT THE SKB IS CONSUMED!!!
                         s = PSTATS_O_PING_FAILED;
                    else s = PSTATS_O_PING_OK;
                }   else { s = PSTATS_O_PING_SKB_FAILED; len = 0; } // PING WAS NOT MADE (BECAUSE SKB WASNT RELEASED BY DEVICE)
// PSTATS_O_PING_PHYS_DOWN
                // NOTE: WE WILL INFORM THE TOTAL SIZE SENT THROUGHT THE PHYSICAL INTERFACE
                atomic_add(&path->pstats[s].bytes, len);
                atomic_inc(&path->pstats[s].count);

                //
                ptr = &path->next;
            } else
               *ptr =  path->next; // NOTE: NOW PATH->NEXT IS INVALID
        }
    }

    // TODO: IF XGW IS DOWN, STOP BEEP
#ifdef CONFIG_XGW_BEEP
    if (beepStatus != BEEP_STATUS_DISABLED) {
        // BEEP IS NOT DISABLED
        if (beepStatus != BEEP_STATUS_SILENT)
            // ESTAVA TOCANDO AGORA PAUSA
            beep = BEEP_STATUS_SILENT;
        if (beepStatus != beep)
            beep_do((beepStatus = beep));
    }
#endif

    add_timer_on(timer, 0);
}

static DEFINE_TIMER(kTimer, keeper);

// TODO: CONFIRMAR QUE NAO ESTA REPETINDO O LINKING DO PING NO LINKED LIST
