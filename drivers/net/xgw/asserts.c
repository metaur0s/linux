BUILD_ASSERT(XGW_MTU_OVERHEAD == (PKT_X_SIZE + PKT_ALIGN_SIZE));

BUILD_ASSERT(PKT_DATA((pkt_s*)NULL) == (NULL + ENCAP_SIZE + XGW_MTU_OVERHEAD));

//
BUILD_ASSERT(sizeof(cmd_arg_nname_t) == sizeof(((node_s*)NULL)->name));
BUILD_ASSERT(sizeof(cmd_arg_pname_t) == sizeof(((path_s*)NULL)->name));
BUILD_ASSERT(sizeof(cmd_arg_addr4_t) == sizeof(((path_s*)NULL)->skel.encap_ip4.ip4.saddr));
BUILD_ASSERT(sizeof(cmd_arg_addr4_t) == sizeof(((path_s*)NULL)->skel.encap_ip4.ip4.daddr));
BUILD_ASSERT(sizeof(cmd_arg_addr6_t) == sizeof(((path_s*)NULL)->skel.encap_ip6.ip6.saddr));
BUILD_ASSERT(sizeof(cmd_arg_addr6_t) == sizeof(((path_s*)NULL)->skel.encap_ip6.ip6.daddr));
BUILD_ASSERT(sizeof(cmd_arg_mac_t)   == sizeof(((path_s*)NULL)->skel.encap_eth.eth.dmac));
BUILD_ASSERT(sizeof(cmd_arg_mac_t)   == sizeof(((path_s*)NULL)->skel.encap_eth.eth.smac));

//
BUILD_ASSERT(sizeof(hdr_eth_s)  == 14);
BUILD_ASSERT(sizeof(hdr_vlan_s) ==  4);
BUILD_ASSERT(sizeof(hdr_ppp_s)  ==  8);
BUILD_ASSERT(sizeof(hdr_ip4_s)  == 20);
BUILD_ASSERT(sizeof(hdr_ip6_s)  == 40);
BUILD_ASSERT(sizeof(hdr_udp_s)  ==  8);
BUILD_ASSERT(sizeof(hdr_tcp_s)  == 20);
BUILD_ASSERT(sizeof(hdr_x_s)    == 24);

//
BUILD_ASSERT(sizeof(encap_eth_s)              == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ip4_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ip6_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ip4_udp_s)      == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ip6_udp_s)      == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_s)         == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ip4_s)     == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ip6_s)     == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ip4_udp_s) == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ip6_udp_s) == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ppp_s)     == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ppp_ip4_s) == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ppp_ip6_s) == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ppp_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ppp_ip4_s)      == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ppp_ip6_s)      == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip4_s)              == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip4_udp_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip4_tcp_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip6_s)              == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip6_udp_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip6_tcp_s)          == ENCAP_SIZE);

//
BUILD_ASSERT(offsetof(pkt_s, x) == ENCAP_SIZE);

//
BUILD_ASSERT(offsetof(pkt_s, encap_raw) == 0);

//
BUILD_ASSERT(sizeof(pkt_s) == (ENCAP_SIZE + sizeof(hdr_x_s)));

BUILD_ASSERT(sizeof(hdr_x_s) == PKT_X_SIZE);
BUILD_ASSERT(sizeof(pkt_s)   == PKT_SIZE);
BUILD_ASSERT(sizeof(ping_s)  == PING_SIZE);

//
BUILD_ASSERT(sizeof(ip4_s) == (sizeof(hdr_ip4_s) + 2 * sizeof(u16)));
BUILD_ASSERT(sizeof(ip6_s) == (sizeof(hdr_ip6_s) + 2 * sizeof(u16)));

//
BUILD_ASSERT(LATENCY_MIN     >= 1);
BUILD_ASSERT(LATENCY_VAR_MIN >= 1);

// MIN < MAX
BUILD_ASSERT(LATENCY_MIN     < LATENCY_MAX);
BUILD_ASSERT(LATENCY_VAR_MIN < LATENCY_VAR_MAX);
BUILD_ASSERT(PATH_TIMEOUT_MIN < PATH_TIMEOUT_MAX);

// TEM QUE TER UMA FOLGUINHA...
BUILD_ASSERT((LATENCY_EFFECTIVE_MAX + 100) < KEEPER_INTERVAL_MS);

//
BUILD_ASSERT(offsetof(path_s,    info) % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(path_s, latency) % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(path_s,  sPorts) % CACHE_LINE_SIZE == 0);

BUILD_ASSERT(offsetof(node_s, opaths)      % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, nid)         % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, syns)        % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, paths)       % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, pstats)      % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, oKeys)       % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, iKeys)       % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, secret)      % CACHE_LINE_SIZE == 0);

BUILD_ASSERT(sizeof(path_s) == PATH_SIZE);

//
BUILD_ASSERT(LATENCY_MIN     >= 1);
BUILD_ASSERT(LATENCY_VAR_MIN >= 1);

//
BUILD_ASSERT((sizeof(((path_s*)NULL)->acks)*8) == ACKS_N);

BUILD_ASSERT(sizeof(((node_s*)NULL)->pstats)
         >= (sizeof(((node_s*)NULL)->pstats[0][0]) * PSTATS_N));

//
BUILD_ASSERT(sizeof(((node_s*)NULL)->oKeys)  == (O_KEYS_ALL * K_SIZE));
BUILD_ASSERT(sizeof(((node_s*)NULL)->iKeys)  == (I_KEYS_ALL * K_SIZE));
BUILD_ASSERT(sizeof(((node_s*)NULL)->secret) == (SECRET_KEYS_N * K_SIZE));
BUILD_ASSERT(sizeof(((node_s*)NULL)->syns)   == 128);
BUILD_ASSERT(sizeof(((node_s*)NULL)->paths)  == 4096);
BUILD_ASSERT(sizeof(((node_s*)NULL)->pstats) == 16384);

// -- NAO PRECISAREMOS CHECAR LIMITES, POIS NAO CABEM MESMO
// -- E TEM QUE CABER TODOS
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->src))     ~(typeof(((hdr_x_s*)NULL)->src))     0 == NID_MAX);
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->dst))     ~(typeof(((hdr_x_s*)NULL)->dst))     0 == NID_MAX);
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->version)) ~(typeof(((hdr_x_s*)NULL)->version)) 0 == I_KEY_MAX);

// THE TYPES MUST BE ABLE TO HOLD THEIR VALUES
BUILD_ASSERT((typeof(((path_s*)NULL)->nid))          NID_MAX          == NID_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->pid))          PID_MAX          == PID_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->latency))      LATENCY_MAX      == LATENCY_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->latency_min))  LATENCY_MAX      == LATENCY_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->latency_max))  LATENCY_MAX      == LATENCY_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->latency_var))  LATENCY_VAR_MAX  == LATENCY_VAR_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->timeout))      PATH_TIMEOUT_MAX == PATH_TIMEOUT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->since))        LTIME_MAX        == LTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->pingSent))     LTIME_MAX        == LTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->pongReceived)) LTIME_MAX        == LTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->pingSeen))     RTIME_MAX        == RTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->pongSeen))     RTIME_MAX        == RTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->info))         P_INFO           == P_INFO);
BUILD_ASSERT((typeof(((path_s*)NULL)->info))         P_ALL            == P_ALL);
BUILD_ASSERT((typeof(((path_s*)NULL)->weight))       PATH_WEIGHT_MAX  == PATH_WEIGHT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->weight_acks))  ACKS_N           == ACKS_N);
BUILD_ASSERT((typeof(((path_s*)NULL)->sPortsN))      PATH_PORTS_N     == PATH_PORTS_N);
BUILD_ASSERT((typeof(((path_s*)NULL)->dPortsN))      PATH_PORTS_N     == PATH_PORTS_N);
BUILD_ASSERT((typeof(((path_s*)NULL)->sPortIndex))   (PATH_PORTS_N-1) == (PATH_PORTS_N-1));
BUILD_ASSERT((typeof(((path_s*)NULL)->dPortIndex))   (PATH_PORTS_N-1) == (PATH_PORTS_N-1));
BUILD_ASSERT((typeof(((node_s*)NULL)->nid))          NID_MAX          == NID_MAX);
BUILD_ASSERT((typeof(((node_s*)NULL)->mtu))          MTU_MAX          == MTU_MAX);
BUILD_ASSERT((typeof(((node_s*)NULL)->weights))      NODE_WEIGHTS_MAX == NODE_WEIGHTS_MAX);
BUILD_ASSERT((typeof(((node_s*)NULL)->kpaths))       KPATH(PID_MAX)   == KPATH(PID_MAX));
BUILD_ASSERT((typeof(((node_s*)NULL)->opaths))       OPATH(PID_MAX)   == OPATH(PID_MAX));
BUILD_ASSERT((typeof(((node_s*)NULL)->ipaths))       IPATH(PID_MAX)   == IPATH(PID_MAX));
BUILD_ASSERT((typeof(((node_s*)NULL)->kpaths))       KPATHS           == KPATHS);
BUILD_ASSERT((typeof(((node_s*)NULL)->opaths))       OPATHS           == OPATHS);
BUILD_ASSERT((typeof(((node_s*)NULL)->ipaths))       IPATHS           == IPATHS);
BUILD_ASSERT((typeof(((node_s*)NULL)->info))         N_INFO           == N_INFO);
BUILD_ASSERT((typeof(((node_s*)NULL)->tdiff))        TDIFF_MIN        == TDIFF_MIN);
BUILD_ASSERT((typeof(((node_s*)NULL)->tdiff))        TDIFF_MAX        == TDIFF_MAX);
BUILD_ASSERT((typeof(((node_s*)NULL)->tlast))        LTIME_MAX        == LTIME_MAX);

BUILD_ASSERT(sizeof(((node_s*)NULL)->secret[0]) == K_SIZE);
BUILD_ASSERT(sizeof(((node_s*)NULL)->secret) == SECRET_SIZE);

//BUILD_ASSERT((typeof(((node_s*)NULL)->info))N_INFO == N_INFO);
//BUILD_ASSERT((typeof(((node_s*)NULL)->connsN))CONNS_N_MAX == CONNS_N_MAX);
