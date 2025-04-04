
// grep CMD_ '{print $1}' cmds.h | grep = | awk -F , | awk '{print "["$1"] = |"$1"|,"}' | tr '|' '"' > cmd_names.h
static const char* const cmdNames [CMDS_N] = {
    [CMD_GWS_CLEAR]            = "CMD_GWS_CLEAR",
    [CMD_GWS_INSERT]           = "CMD_GWS_INSERT",
    [CMD_GWS_LIST]             = "CMD_GWS_LIST",
    [CMD_GWS_REMOVE]           = "CMD_GWS_REMOVE",
    [CMD_NMAP]                 = "CMD_NMAP",
    [CMD_NODE_CLR_NAME]        = "CMD_NODE_CLR_NAME",
    [CMD_NODE_CLR_SECRET]      = "CMD_NODE_CLR_SECRET",
    [CMD_NODE_DEL]             = "CMD_NODE_DEL",
    [CMD_NODE_DEV_CREATE]      = "CMD_NODE_DEV_CREATE",
    [CMD_NODE_DEV_DEL]         = "CMD_NODE_DEV_DEL",
    [CMD_NODE_NEW]             = "CMD_NODE_NEW",
    [CMD_NODE_OFF]             = "CMD_NODE_OFF",
    [CMD_NODE_ON]              = "CMD_NODE_ON",
    [CMD_NODE_SET_CONNS_N]     = "CMD_NODE_SET_CONNS_N",
    [CMD_NODE_SET_MTU]         = "CMD_NODE_SET_MTU",
    [CMD_NODE_SET_NAME]        = "CMD_NODE_SET_NAME",
    [CMD_NODE_SET_SECRET]      = "CMD_NODE_SET_SECRET",
    [CMD_NODE_STATS]           = "CMD_NODE_STATS",
    [CMD_NODE_STATUS]          = "CMD_NODE_STATUS",
    [CMD_PATH_CLR_DHCP]        = "CMD_PATH_CLR_DHCP",
    [CMD_PATH_CLR_ETH_DST]     = "CMD_PATH_CLR_ETH_DST",
    [CMD_PATH_CLR_ETH_SRC]     = "CMD_PATH_CLR_ETH_SRC",
    [CMD_PATH_CLR_IP4_DST]     = "CMD_PATH_CLR_IP4_DST",
    [CMD_PATH_CLR_IP4_SRC]     = "CMD_PATH_CLR_IP4_SRC",
    [CMD_PATH_CLR_IP4_TOS]     = "CMD_PATH_CLR_IP4_TOS",
    [CMD_PATH_CLR_IP4_TTL]     = "CMD_PATH_CLR_IP4_TTL",
    [CMD_PATH_CLR_IP6_DST]     = "CMD_PATH_CLR_IP6_DST",
    [CMD_PATH_CLR_IP6_SRC]     = "CMD_PATH_CLR_IP6_SRC",
    [CMD_PATH_CLR_IP6_TOS]     = "CMD_PATH_CLR_IP6_TOS",
    [CMD_PATH_CLR_IP6_TTL]     = "CMD_PATH_CLR_IP6_TTL",
    [CMD_PATH_CLR_NAME]        = "CMD_PATH_CLR_NAME",
    [CMD_PATH_CLR_PHYS]        = "CMD_PATH_CLR_PHYS",
    [CMD_PATH_CLR_TCP_DST]     = "CMD_PATH_CLR_TCP_DST",
    [CMD_PATH_CLR_TCP_SRC]     = "CMD_PATH_CLR_TCP_SRC",
    [CMD_PATH_CLR_TYPE]        = "CMD_PATH_CLR_TYPE",
    [CMD_PATH_CLR_UDP_DST]     = "CMD_PATH_CLR_UDP_DST",
    [CMD_PATH_CLR_UDP_SRC]     = "CMD_PATH_CLR_UDP_SRC",
    [CMD_PATH_CLR_VLAN_ID]     = "CMD_PATH_CLR_VLAN_ID",
    [CMD_PATH_CLR_VLAN_PROTO]  = "CMD_PATH_CLR_VLAN_PROTO",
    [CMD_PATH_CLR_WEIGHT_ACKS] = "CMD_PATH_CLR_WEIGHT_ACKS",
    [CMD_PATH_CLR_WEIGHT_NODE] = "CMD_PATH_CLR_WEIGHT_NODE",
    [CMD_PATH_DEL]             = "CMD_PATH_DEL",
    [CMD_PATH_NEW]             = "CMD_PATH_NEW",
    [CMD_PATH_OFF]             = "CMD_PATH_OFF",
    [CMD_PATH_ON]              = "CMD_PATH_ON",
    [CMD_PATH_SET_CLIENT]      = "CMD_PATH_SET_CLIENT",
    [CMD_PATH_SET_DHCP]        = "CMD_PATH_SET_DHCP",
    [CMD_PATH_SET_ETH_DST]     = "CMD_PATH_SET_ETH_DST",
    [CMD_PATH_SET_ETH_SRC]     = "CMD_PATH_SET_ETH_SRC",
    [CMD_PATH_SET_IP4_DST]     = "CMD_PATH_SET_IP4_DST",
    [CMD_PATH_SET_IP4_SRC]     = "CMD_PATH_SET_IP4_SRC",
    [CMD_PATH_SET_IP4_TOS]     = "CMD_PATH_SET_IP4_TOS",
    [CMD_PATH_SET_IP4_TTL]     = "CMD_PATH_SET_IP4_TTL",
    [CMD_PATH_SET_IP6_DST]     = "CMD_PATH_SET_IP6_DST",
    [CMD_PATH_SET_IP6_SRC]     = "CMD_PATH_SET_IP6_SRC",
    [CMD_PATH_SET_IP6_TOS]     = "CMD_PATH_SET_IP6_TOS",
    [CMD_PATH_SET_IP6_TTL]     = "CMD_PATH_SET_IP6_TTL",
    [CMD_PATH_SET_IP_TOS]      = "CMD_PATH_SET_IP_TOS",
    [CMD_PATH_SET_IP_TTL]      = "CMD_PATH_SET_IP_TTL",
    [CMD_PATH_SET_NAME]        = "CMD_PATH_SET_NAME",
    [CMD_PATH_SET_PHYS]        = "CMD_PATH_SET_PHYS",
    [CMD_PATH_SET_PPP_SESSION] = "CMD_PATH_SET_PPP_SESSION",
    [CMD_PATH_SET_RTT_VAR]     = "CMD_PATH_SET_RTT_VAR",
    [CMD_PATH_SET_SERVER]      = "CMD_PATH_SET_SERVER",
    [CMD_PATH_SET_TCP_DST]     = "CMD_PATH_SET_TCP_DST",
    [CMD_PATH_SET_TCP_SRC]     = "CMD_PATH_SET_TCP_SRC",
    [CMD_PATH_SET_TIMEOUT___]  = "CMD_PATH_SET_TIMEOUT",
    [CMD_PATH_SET_TYPE]        = "CMD_PATH_SET_TYPE",
    [CMD_PATH_SET_UDP_DST]     = "CMD_PATH_SET_UDP_DST",
    [CMD_PATH_SET_UDP_SRC]     = "CMD_PATH_SET_UDP_SRC",
    [CMD_PATH_SET_VLAN_ID]     = "CMD_PATH_SET_VLAN_ID",
    [CMD_PATH_SET_VLAN_PROTO]  = "CMD_PATH_SET_VLAN_PROTO",
    [CMD_PATH_SET_WEIGHT_ACKS] = "CMD_PATH_SET_WEIGHT_ACKS",
    [CMD_PATH_SET_WEIGHT_NODE] = "CMD_PATH_SET_WEIGHT_NODE",
    [CMD_PATH_STATS]           = "CMD_PATH_STATS",
    [CMD_PATH_STATUS]          = "CMD_PATH_STATUS",
    [CMD_PHYS_ATTACH]          = "CMD_PHYS_ATTACH",
    [CMD_PHYS_DETACH]          = "CMD_PHYS_DETACH",
    [CMD_PHYS_LIST]            = "CMD_PHYS_LIST",
    [CMD_PORT_GET]             = "CMD_PORT_GET",
    [CMD_PORT_OFF]             = "CMD_PORT_OFF",
    [CMD_PORT_ON]              = "CMD_PORT_ON",
    [CMD_PORTS_CLEAR]          = "CMD_PORTS_CLEAR",
    [CMD_PORTS_LIST]           = "CMD_PORTS_LIST",
    [CMD_SELF_GET]             = "CMD_SELF_GET",
    [CMD_SELF_SET]             = "CMD_SELF_SET",
    [CMD_STATS]                = "CMD_STATS",
};
