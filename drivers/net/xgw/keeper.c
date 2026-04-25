
static inline void keeper_send_pings (void) {

    // SEND PINGS
    for_count (q, PING_QUEUES_N) {

        path_s** ptr = &pings[q]; path_s* path;

        while ((path = *ptr)) {
            if (path->info & K_ESTABLISHED) {

                ASSERT((path->asked    >= PTIME_MIN &&
                        path->asked    <= PTIME_MAX) ||
                        path->asked    == 0);
                ASSERT((path->answered >= PTIME_MIN && 
                        path->answered <= PTIME_MAX) ||
                        path->answered == ANSWERED_CONNECTING);
                ASSERT(path->mask     >= PMASK_MIN);
                ASSERT(path->mask     <= PMASK_MAX);
                ASSERT(path->tdiff    >= TDIFF_MIN);
                ASSERT(path->tdiff    <= TDIFF_MAX);

                const u64 now = path->mask + get_current_ms();

                ASSERT(now >= PTIME_MIN);
                ASSERT(now <= PTIME_MAX);

                __atomic_store_n(&path->asked, now, __ATOMIC_RELAXED);

                const uint o =
                    atomic_get(&path->answered) == ANSWERED_CONNECTING ?
                        O_KEY_SYN :
                        O_KEY_PING;

                const u64 rtime = (o == O_KEY_SYN) ?
                    path->syn : RTIME(now, atomic_get(&path->tdiff));

#if 0
                ASSERT((rtime >= PTIME_MIN &&
                        rtime <= PTIME_MAX) ||
                        rtime == path->syn);
#endif
                if (!((rtime >= PTIME_MIN &&
                        rtime <= PTIME_MAX) ||
                        rtime == path->syn)) {
                    printk("XGW: CRAZY: NODE [%s] PATH [%s] now = 0x%016llX rtime = 0x%016llX tdiff %lld \n",
                            path->node->name,
                            path->name,
                            (uintll)now,
                            (uintll)rtime,
                            (long long int)path->tdiff
                        );
                }

                // NOTE: RESERVA HEAD AND TAIL ROOM POIS PODE TER MAIS ENCAPSULAMENTOS NO PHYS
                ping_send(path->node, path, &path->skel, now, rtime, o);

                ptr = &path->next;
            } else // NOTE: NOW PATH->NEXT IS INVALID
               *ptr =  path->next;
        }
    }
}

static void keeper (struct timer_list* const timer) {

    // jiffies +
    timer->expires += KEEPER_INTERVAL_JIFFIES;

#ifdef CONFIG_XGW_BEEP
    uint beep = 0; // O OBJETIVO É BEEPAR CONFORME A SITUAÇÃO DO PIOR node
    // CONFORME OS NODES
#endif

    // LOCK
    unsigned long iflags;

    spin_lock_irqsave(&xlock, iflags);

    const u64 _now = get_current_ms();

    for (node_s* node = knodes; node; node = node->next) {

        ASSERT(!node_is_off(node));
        ASSERT(*node->ptr == node);
        ASSERT(node->info & N_CONNS_N);
        ASSERT(node->info & N_MTU);
        ASSERT(node->info & N_NAME);
     // ASSERT(node->info & N_OADD);
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
        ASSERT(node->oVersions[O_KEY_PING] == I_KEY_PING);

#ifdef CONFIG_XGW_BEEP // SITUACAO DESTE NODE, CONFORME OS PATHS
        uint stableWeights = 0, stableSum = 0;
#endif

        // BUILD
        u64 opaths = 0;

        // ITERATE
        uint kpaths = node->kpaths;

        while (kpaths) { const uint pid = __ctz(kpaths); kpaths ^= KPATH(pid);

            path_s* const path = &node->paths[pid];

            ASSERT(path->node == node);
            ASSERT(path->rtt <= RTT_MAX);
            ASSERT(path->rtt_max <= RTT_MAX);
            ASSERT(path->rtt <= path->rtt_max);
            ASSERT(path->rtt_var_ >= RTT_VAR_MIN);
            ASSERT(path->rtt_var_ <= RTT_VAR_MAX);
            ASSERT(path->rtt_var >= RTT_VAR_MIN);
            ASSERT(path->rtt_var <= RTT_VAR_MAX_INIT);
            ASSERT(path->rtt_var >= path->rtt_var_);
            ASSERT(path->cdown <= RTT_VAR_STEPS);
            ASSERT(path->tdiff >= TDIFF_MIN);
            ASSERT(path->tdiff <= TDIFF_MAX);
            ASSERT((path->asked    >= PTIME_MIN &&
                    path->asked    <= PTIME_MAX) ||
                    path->asked    == 0);
            ASSERT((path->answered >= PTIME_MIN && 
                    path->answered <= PTIME_MAX) ||
                    path->answered == ANSWERED_LISTENING || 
                    path->answered == ANSWERED_ACCEPTING || 
                    path->answered == ANSWERED_CONNECTING);
            ASSERT(path->mask >= PMASK_MIN);
            ASSERT(path->mask <= PMASK_MAX);
            ASSERT(path->oadd >= PATH_OADD_MIN);
            ASSERT(path->oadd <= PATH_OADD_MAX);

            if (path->info & K_START) { //231956

                if (path->info & P_CLIENT) {

#if 0
                    if (path->info & P_DHCP) {

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
                            // CANNOT START YET
                            goto _skip;
                    }
#endif

                    // THE TTL AND TOS ARE STORED OUTSIDE THE SKEL, OTHERWISE WE LOSE THEM ON EVERY IN-DISCOVER.
                    // SO, THE CMD ALSO STORED THEM DIRECTLY ON PATH.
                    // HERE WE COPY THEM TO THE SKEL
                    if (path_is_ip4(path)) { hdr_ip4_s* const ip4 = PKT_IP4(&path->skel);
                        ip4->tos = BE8(path->tos);
                        ip4->ttl = BE8(path->ttl);
                    } elif (path_is_ip6(path)) { hdr_ip6_s* const ip6 = PKT_IP6(&path->skel);
                        ip6->tos = BE8(path->tos);
                        ip6->ttl = BE8(path->ttl);
                        ip6->flow = BE16(SKEL_IP6_FLOW(node, path));
                    }

                    // TODO: PRECOMPUTE TCP CHECKSUM
                    // TODO: PRECOMPUTE UDP CHECKSUM (FOR IPV6)
                    if (path_is_udp_tcp(path)) {
                        path->sPortIndex = ((uint)path->sPortIndex + 1                      ) % path->sPortsN;
                        path->dPortIndex = ((uint)path->dPortIndex + (path->sPortIndex == 0)) % path->dPortsN;
                        // BOTH UDP AND TCP PORTS START ON TRANSPORT
                        hdr_udp_s* const udp = PKT_UDP(&path->skel);
                        udp->sport = BE16(path->sPorts[path->sPortIndex]);
                        udp->dport = BE16(path->dPorts[path->dPortIndex]);
                    }

                    // TODO: FAZER ISSO A TODOS OS NODES-PATHS AO SETAR O SELF
                    // TODO: TEM QUE REPENSAR O CRYPTO DERIVATE, POIS SENAO SE MUDAR O SELF, TERA DE SETAR NOVAMENTE O SECRET
                    path->skel.x.src   = BE16(nodeSelf);
                    path->acks         = ACKS_CLIENT;
                    path->answered     = ANSWERED_CONNECTING;
                } else {
                    printk("XGW: %s [%s]: LISTENING\n", node->name, path->name);
                    path->skel.type    = 0; //
                    path->acks         = ACKS_SERVER;
                    path->answered     = ANSWERED_LISTENING;
                }   path->asked        = 0; // AINDA NAO ENVIEI PING
                    path->pseen[0]     = 0;
                    path->pseen[1]     = 0;
                    path->rtt          = path->rtt_max / 2;
                    path->rtt_var      = path->rtt_var_ + RTT_VAR_STEPS * RTT_VAR_STEP;
                    path->cdown        = RTT_VAR_STEPS;
                    path->info        ^= K_START | K_LISTEN;
                    path->since        = 0;
                    path->tdiff        = 0;
                    path->mask         = PMASK_MIN + (random64(_now) % (PMASK_MAX - PMASK_MIN));
                 // path->olatency   == ?

                // ENABLE IN
                // NOTE: AQUI ENTAO TEM UM RACE CONDITION, ELE PODE RECEBER UM PING/PONG E COMO SERÁ INTERPRETADO?
                __atomic_store_n(&node->ipaths, node->ipaths | IPATH(pid), __ATOMIC_SEQ_CST);
            }

            if (path->info & K_LISTEN) {

                if (__atomic_load_n(&path->answered, __ATOMIC_SEQ_CST) >= ANSWERED_CONNECTING) {

                    printk("XGW: %s [%s]: %s ON PHYS %s WITH RTT %u +%u\n",
                        node->name, path->name, (path->info & P_SERVER) ? "ACCEPTED" : "CONNECTING", path->skel.phys->name, (uint)path->rtt, (uint)path->rtt_var);

             ASSERT(path->since    == 0);
                    path->info     ^= K_LISTEN | K_ESTABLISHED;
                    path->since     = _now;
                 // AT THIS POINT, THE PATH->SKEL WAS BUILT
                 //      a) FROM USER (CMD)
                 //      b) FROM IN (DISCOVER)
             ASSERT(path->skel.x.src  == BE16(nodeSelf));
             ASSERT(path->skel.x.dst  == BE16(node->nid));
             ASSERT(path->skel.x.path == BE8 (PATH_ID(node, path)));
                 // path->skel.x.version --> ON encrypt()
                 // path->skel.x.dsize   --> ON encrypt()
                 // path->skel.x.time    --> ON encrypt()
                 // path->skel.x.hash    --> ON encrypt()
             ASSERT(path->skel.phys);

                    // PASSA A ENVIAR PINGS
                    const uint q = path->skel.phys->ifindex % PING_QUEUES_N;

                    path->next = pings[q];
                                 pings[q] = path;
                }
            }

            if (path->info & K_ESTABLISHED) {

                u64 acks;

                const u64 answered = atomic_get(&path->answered);

                ASSERT((answered >= PTIME_MIN && 
                        answered <= PTIME_MAX) ||
                        answered == ANSWERED_CONNECTING);

                // SE NAO RECEBEU UM PONG, ESTE RTT SERÁ UM OVERFLOW
                // É POR ISSO QUE ANSWERED_CONNECTING TEM QUE SER MAIOR DO QUE O RTT_MAX,
                // POIS SE O ASKED ESTIVER ZERADO,
                // QUALQUER PATH->ANSWERED QUE NAO SEJA O LAST PING ENVIADO,
                // TEM QUE RESULTAR EM > RTT_MAX
                const uint took = answered - path->asked;

                if (took <= RTT_MAX) {
                    // AVERAGE, CAPPED TO LIMITS
                    uint rtt = ((uint)path->rtt*7 + took*1) / (7 + 1);
                    if (rtt > path->rtt_max)
                        rtt = path->rtt_max;
                    // SAVE THE NEW AVERAGE
                    if (path->cdown) {
                        path->cdown--;
                        __atomic_store_n(&path->rtt_var, path->rtt_var - RTT_VAR_STEP, __ATOMIC_RELAXED);
                    }  // __atomic_store_n(&path->olatency, (rtt + path->rtt_var)/2 + path->oadd, __ATOMIC_RELAXED);
                        __atomic_store_n(&path->rtt, rtt, __ATOMIC_RELAXED);
                    // A SECOND ELAPSED
                    acks = (path->acks >> 1) | ((u64)(took <= (rtt + path->rtt_var)) << (ACKS_N - 1));
                } else
                    acks = (path->acks >> 1);

                if (path->acks != acks) {
                    path->acks = acks;
                    // CHANGED

                    const char* str;

                    switch (acks) {
                        case 0b0000000000000000000000000000000000000000000000000000000000000000ULL: str = "LOST";       break;
                        case 0b1000000000000000000000000000000000000000000000000000000000000000ULL: str = "RECOVERING"; break;
                        case 0b0111111111111111111111111111111111111111111111111111111111111111ULL: str = "UNSTABLE";   break;
                        case 0b1111111111111111111111111111111111111111111111111111111111111111ULL: str = "STABLE";     break;
                        default:                                                                    str = NULL;
                    }

                    if (str) {
                        if (took <= RTT_MAX)
                            printk("XGW: %s [%s]: RTT %u +%u; %s; PONG TOOK %u\n", node->name, path->name, (uint)path->rtt, (uint)path->rtt_var, str, took);
                        else
                            printk("XGW: %s [%s]: RTT %u +%u; %s; PONG LOST\n", node->name, path->name, (uint)path->rtt, (uint)path->rtt_var, str);
                    }

                } elif (!acks) {
                    // TIMED OUT WAITING FOR PONGS
                    printk("XGW: %s [%s]: TIMED OUT\n", node->name, path->name);
                    goto _suspend;
                }

                // DOS PIORES AOS MELHORES
                opaths |= ( // TEM QUE CONSIDERAR QUE ELE VAI ENTRAR NA FRENTE DOS OUTROS ENTAO PERDER 1 PONG E RECEBER UM VAI FORCAR A TROCA E FERRAR A ESTABILIDADE DAS STREAMS
                    ((u64)(acks >= 0b000000010000000000000000000000000000000000000000ULL) << (3*PATHS_N)) | // BASTA QUE ESTEJA FUNCIONANDO ENTAO
                    ((u64)(acks >= 0b010111111110000000000000000000000000000000000000ULL) << (2*PATHS_N)) |
                    ((u64)(acks >= 0b111111111111111111110000000000000000000000000000ULL) << (1*PATHS_N)) | // NOTE: THIS ONE SHOULD BE REPEATED
                    ((u64)(acks >= 0b111111111111111111110000000000000000000000000000ULL) << (0*PATHS_N)) // TODO: REMOVE THIS REPETITION LIMITATION
                ) << pid;
            }

            if (path->info & K_SUSPEND) { // NOTE: WILL EXECUTE TWICE BECAUSE THE ATOMIC EXCHANTE BELOW
_suspend:
                // STOP IN
                // STOP PING (BY REMOVING K_ESTABLISHED)
                // STOP OUT (BY NOT INCLUDING IN OPATHS)
                path->info  = (path->info & P_INFO) | K_SUSPENDING;
                path->acks  = 0; // PARA JA ATUALIZAR O BEEP
                path->since = 0;

                __atomic_store_n(&node->ipaths, node->ipaths & ~IPATH(pid), __ATOMIC_RELAXED);

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

    keeper_send_pings();

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
