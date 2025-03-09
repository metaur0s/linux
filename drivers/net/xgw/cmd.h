
/*
    TODO: HIDE, INACCESS, UNLIST?

    COMO A INTERFACE PODE ESTAR HIDDEN, VAI TER QUE TER UMA LISTA LOCAL DE INTERFACES KNOWN

    list_netdevice
    unlist_netdevice

    CMD_PHYS_SET_DONT_GET,
    CMD_PHYS_SET_DONT_LIST,
    CMD_PHYS_SET_DROP_ARP,
    CMD_PHYS_SET_DROP_IP4,
    CMD_PHYS_SET_DROP_IP6,
    CMD_PHYS_SET_DROP_8021Q,
    CMD_PHYS_SET_DROP_8021AD,
    CMD_PHYS_SET_DROP_OTHER,

    CMD_PHYS_CLR_DONT_GET,
    CMD_PHYS_CLR_DONT_LIST,
    CMD_PHYS_CLR_DROP_ARP,
    CMD_PHYS_CLR_DROP_IP4,
    CMD_PHYS_CLR_DROP_IP6,
    CMD_PHYS_CLR_DROP_8021Q,
    CMD_PHYS_CLR_DROP_8021AD,
    CMD_PHYS_CLR_DROP_OTHER,

    CMD_PHYS_MTU,
    CMD_PHYS_QUEUE_LEN,
    CMD_PHYS_HWADDR,
    CMD_PHYS_PROMISC_ON,
    CMD_PHYS_PROMISC_OFF,
*/

enum CMD {

    // PORT
    CMD_PORT_ON,
    CMD_PORT_OFF,
    CMD_PORT_GET,

    // PORTS
    CMD_PORTS_LIST,
    CMD_PORTS_CLEAR,

    // NOTE: SAME ORDER AS IN IFF_XGW*
    CMD_PHYS_ATTACH,
    CMD_PHYS_DETACH,

    CMD_PHYS_LIST,

    // SELF NODE
    CMD_SELF_SET,
    CMD_SELF_GET,

    // GWS
    CMD_GWS_INSERT,
    CMD_GWS_REMOVE,
    CMD_GWS_LIST,
    CMD_GWS_CLEAR,

    // NODE
    CMD_NODE_NEW,
    CMD_NODE_DEL,

    CMD_NODE_SET_NAME,
    CMD_NODE_SET_MTU,
    CMD_NODE_SET_CONNS_N,
    CMD_NODE_SET_SECRET,

    CMD_NODE_DEV_CREATE,
    CMD_NODE_DEV_DEL,

    CMD_NODE_CLR_NAME,
    CMD_NODE_CLR_SECRET,

    CMD_NODE_ON,
    CMD_NODE_OFF,

    CMD_NODE_STATUS,
    CMD_NODE_STATS,

    // PATH
    CMD_PATH_NEW,
    CMD_PATH_DEL,

    CMD_PATH_SET_NAME,
    CMD_PATH_SET_WEIGHT_NODE,
    CMD_PATH_SET_WEIGHT_ACKS,
    CMD_PATH_SET_CLIENT,
    CMD_PATH_SET_SERVER,
    CMD_PATH_SET_TIMEOUT,
    CMD_PATH_SET_LATENCY_MIN,
    CMD_PATH_SET_LATENCY_MAX,
    CMD_PATH_SET_LATENCY_VAR,
    CMD_PATH_SET_DHCP,
    CMD_PATH_SET_PHYS, // SET THE PATH PHYS
    CMD_PATH_SET_TYPE, // SET THE PATH ENCAPSULATING TYPE
    CMD_PATH_SET_ETH_SRC,
    CMD_PATH_SET_ETH_DST,
    CMD_PATH_SET_VLAN_PROTO, // 8021Q / 8021AD  na verdade seria ETH PROTO, MAS SO USADO NO CASO DO VLAN
    CMD_PATH_SET_VLAN_ID,
    CMD_PATH_SET_IP4_TOS,
    CMD_PATH_SET_IP6_TOS,
    CMD_PATH_SET_IP4_TTL,
    CMD_PATH_SET_IP6_TTL,
    CMD_PATH_SET_IP4_SRC,
    CMD_PATH_SET_IP4_DST,
    CMD_PATH_SET_IP6_SRC,
    CMD_PATH_SET_IP6_DST,
    CMD_PATH_SET_UDP_SRC,
    CMD_PATH_SET_TCP_SRC,
    CMD_PATH_SET_UDP_DST,
    CMD_PATH_SET_TCP_DST,

    CMD_PATH_SET_PPP_SESSION,

    CMD_PATH_SET_IP_TOS, // PARA O CASO DO SERVER
    CMD_PATH_SET_IP_TTL,

    CMD_PATH_CLR_NAME,
    CMD_PATH_CLR_WEIGHT_NODE,
    CMD_PATH_CLR_WEIGHT_ACKS,
    CMD_PATH_CLR_DHCP,
    CMD_PATH_CLR_PHYS,
    CMD_PATH_CLR_TYPE, // UNSET THE PATH ENCAPSULATING TYPE AND CLEAR ALL INFO
    CMD_PATH_CLR_ETH_SRC,
    CMD_PATH_CLR_ETH_DST,
    CMD_PATH_CLR_VLAN_PROTO,
    CMD_PATH_CLR_VLAN_ID,
    CMD_PATH_CLR_IP4_TOS,
    CMD_PATH_CLR_IP6_TOS,
    CMD_PATH_CLR_IP4_TTL,
    CMD_PATH_CLR_IP6_TTL,
    CMD_PATH_CLR_IP4_SRC,
    CMD_PATH_CLR_IP4_DST,
    CMD_PATH_CLR_IP6_SRC,
    CMD_PATH_CLR_IP6_DST,
    CMD_PATH_CLR_UDP_SRC,
    CMD_PATH_CLR_TCP_SRC,
    CMD_PATH_CLR_UDP_DST,
    CMD_PATH_CLR_TCP_DST,

    CMD_PATH_ON,
    CMD_PATH_OFF,

    CMD_PATH_STATUS,
    CMD_PATH_STATS,

    // GLOBAL
    CMD_STATS,

    CMD_NMAP

};

#define CMDS_N (CMD_NMAP + 1)

#define C_USE_NID(C)    (((C) >= CMD_NODE_NEW && (C) <= CMD_PATH_STATS) || (C) == CMD_SELF_SET || ((C) >= CMD_GWS_INSERT && (C) <= CMD_GWS_REMOVE) || (C) == CMD_NMAP)
#define C_USE_PID(C)    ((C) >= CMD_PATH_NEW && (C) <= CMD_PATH_STATS)

#define C_USE_NODE(C) ( \
    (CMD_NODE_NEW <= (C) && (C) <= CMD_NODE_STATUS) || \
    (CMD_PATH_NEW <= (C) && (C) <= CMD_PATH_STATUS) )

#define C_USE_PATH(C) (CMD_PATH_NEW <= (C) && (C) <= CMD_PATH_STATUS)

#define C_USE_PHYS(C) ((CMD_PHYS_ATTACH <= (C) && (C) <= CMD_PHYS_DETACH) || (C) == CMD_PATH_SET_PHYS)

#define C_USE_PORTS(C) ( \
    (CMD_PORT_ON        <= (C) && (C) <= CMD_PORT_GET) || \
    (CMD_PATH_SET_UDP_SRC <= (C) && (C) <= CMD_PATH_SET_UDP_DST) )

#define C_NODE_MUST_EXIST(C) ((C) > CMD_NODE_NEW && (C) <= CMD_PATH_STATS)
#define C_PATH_MUST_EXIST(C) ((C) > CMD_PATH_NEW && (C) <= CMD_PATH_STATS)

#define C_NODE_MUST_NOT_EXIST(C) ((C) == CMD_NODE_NEW)
#define C_PATH_MUST_NOT_EXIST(C) ((C) == CMD_PATH_NEW)

#define C_NODE_MUST_BE_OFF_IDLE(C) ((C) >= CMD_NODE_DEL && (C) <= CMD_NODE_ON)
#define C_PATH_MUST_BE_OFF_IDLE(C) ((C) >= CMD_PATH_DEL && (C) <= CMD_PATH_ON)

// TODO: RELACAO TIPO DE DHCP VS TIPO DE PATH
//      VAI TER QUE FORCAR TIPO DE PATH COMPATIVEL COM O TIPO DE DHCP, E VICE-VERSA
//      COPIAR O DEV DO DHCP

#include "cmd_errs.h"

// CHECK IF THE COMMAND MESSAGE IS COMPLETE
#define _CMD_ARG_SIZE(a, b, c) sizeof(a ## b ## c)
#define CMD_ARG_SIZE(arg) _CMD_ARG_SIZE(cmd_arg_, arg, _t)

#define _CMD_VALUE(a, b, c) (*(a ## b ## c)cmd)
#define CMD_VALUE(arg) _CMD_ARG_SIZE(cmd_arg_, arg, _t)

#define _CMD_CONSUME(_type) { \
    ASSERT(size >= CMD_ARG_SIZE(_type)); \
    size -= CMD_ARG_SIZE(_type); \
    cmd = PTR(cmd) + CMD_ARG_SIZE(_type); \
}

#define CMD_SIZE_MIN  CMD_ARG_SIZE(code)
#define CMD_SIZE_MAX (CMD_ARG_SIZE(code) + CMD_ARG_SIZE(nid) + CMD_ARG_SIZE(password))

typedef u8  cmd_arg_code_t;
typedef u16 cmd_arg_nid_t;
typedef u8  cmd_arg_pid_t;
typedef u8  cmd_arg_did_t;
typedef u32 cmd_arg_connsN_t;
typedef u16 cmd_arg_mtu_t;
typedef u16 cmd_arg_eProto_t;
typedef u16 cmd_arg_vID_t;
typedef u8  cmd_arg_tos_t;
typedef u8  cmd_arg_ttl_t;
typedef u8  cmd_arg_type_t;
typedef u8  cmd_arg_weight_node_t;
typedef u8  cmd_arg_weight_acks_t;
typedef u8  cmd_arg_timeout_t;
typedef u16 cmd_arg_latency_t;
typedef u16 cmd_arg_latency_var_t;
typedef u16 cmd_arg_ppp_session_t;

typedef struct { char _[NODE_NAME_SIZE];    } cmd_arg_nname_t;
typedef struct { char _[PATH_NAME_SIZE];    } cmd_arg_pname_t;
typedef struct { char _[DHCP_NAME_SIZE];    } cmd_arg_dname_t;
typedef struct { char _[IFNAMSIZ];          } cmd_arg_phys_t;
typedef struct { u8   _[PASSWORD_SIZE_MAX]; } cmd_arg_password_t;
typedef struct { u8   _[ETH_ALEN];          } cmd_arg_mac_t;
typedef struct { u16  _[PATH_PORTS_N];      } cmd_arg_path_ports_t;
typedef struct { u8   _[4];                 } cmd_arg_addr4_t;
typedef struct { u16  _[8];                 } cmd_arg_addr6_t;
typedef struct { u16  _[PORTS_N];           } cmd_arg_ports_t;

// CMD SIZES:
// AQUELES QUE USAM PORTA: CONSIDERA O TAMANHO MINIMO DE 1 PORTA, MAS EMBAIXO CHECA TAMBEM O MAXIMO
// SECRET_SET: SIZE:  // LEMBRAR DE VERIFICAR EMBAIXO TAMBEM,
typedef struct { u16 _[1]; } cmd_arg_ports_min_t;
typedef struct { u8 _[16]; } cmd_arg_secret_min_t;
