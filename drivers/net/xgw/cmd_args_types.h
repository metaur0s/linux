// CHECK IF THE COMMAND MESSAGE IS COMPLETE

#define _CMD_JOIN(a, arg, b) a ## arg ## b

#define CMD_TYPE(arg)    _CMD_JOIN(CMD_, arg, _TYPE)
#define CMD_LEN(arg)     _CMD_JOIN(CMD_, arg, _LEN)
#define CMD_LEN_MIN(arg) _CMD_JOIN(CMD_, arg, _LEN_MIN)
#define CMD_LEN_MAX(arg) _CMD_JOIN(CMD_, arg, _LEN_MAX)

#define CMD_SIZE(arg)      (sizeof(CMD_TYPE(arg)) * CMD_LEN(arg))
#define CMD_SIZE_MIN(arg)  (sizeof(CMD_TYPE(arg)) * CMD_LEN_MIN(arg))
#define CMD_SIZE_MAX(arg)  (sizeof(CMD_TYPE(arg)) * CMD_LEN_MAX(arg))
#define CMD_SIZE_N(arg, n) (sizeof(CMD_TYPE(arg)) * (n))

#define CMD_VALUE(arg) ((const CMD_TYPE(arg)*)cmd)

#define _CMD_CONSUMED(_size) { \
    ASSERT(size >= (_size)); \
    size -= (_size); \
    cmd = PTR(cmd) + (_size); \
}

#define CMD_CONSUMED(arg)     _CMD_CONSUMED(CMD_SIZE(arg))
#define CMD_CONSUMED_MIN(arg) _CMD_CONSUMED(CMD_SIZE_MIN(arg))
#define CMD_CONSUMED_MAX(arg) _CMD_CONSUMED(CMD_SIZE_MAX(arg))
#define CMD_CONSUMED_N(arg)   _CMD_CONSUMED(CMD_SIZE_N(arg, n))

// SMALLEST AND BIGGEST COMMANDS POSSIBLE
#define CMD_TOTAL_SIZE_MIN  CMD_SIZE(CODE)
#define CMD_TOTAL_SIZE_MAX (CMD_SIZE(CODE) + CMD_SIZE(NODE_ID) + CMD_SIZE_MAX(PASSWORD))

#define CMD_ADDR4_LEN          4
#define CMD_ADDR4_TYPE         u8
#define CMD_ADDR6_LEN          8
#define CMD_ADDR6_TYPE         u16
#define CMD_CODE_LEN           1
#define CMD_CODE_TYPE          u8
#define CMD_CONNS_N_LEN        1
#define CMD_CONNS_N_TYPE       u32
#define CMD_DID_LEN            1
#define CMD_DID_TYPE           u8
#define CMD_DNAME_LEN          DHCP_NAME_SIZE
#define CMD_DNAME_TYPE         char
#define CMD_ETH_PROTO_LEN      1
#define CMD_ETH_PROTO_TYPE     u16
#define CMD_MAC_LEN            ETH_ALEN
#define CMD_MAC_TYPE           u8
#define CMD_MTU_LEN            1
#define CMD_MTU_TYPE           u16
#define CMD_NODE_ID_LEN        1
#define CMD_NODE_ID_TYPE       u16
#define CMD_NODE_NAME_LEN      NODE_NAME_SIZE
#define CMD_NODE_NAME_TYPE     char
#define CMD_PASSWORD_LEN_MAX   PASSWORD_SIZE_MAX
#define CMD_PASSWORD_LEN_MIN   PASSWORD_SIZE_MIN
#define CMD_PASSWORD_TYPE      u8
#define CMD_PATH_ID_LEN        1
#define CMD_PATH_ID_TYPE       u8
#define CMD_PATH_NAME_LEN      PATH_NAME_SIZE
#define CMD_PATH_NAME_TYPE     char
#define CMD_PATH_PORTS_LEN_MAX PATH_PORTS_N
#define CMD_PATH_PORTS_LEN_MIN 1
#define CMD_PATH_PORTS_TYPE    u16
#define CMD_PHYS_LEN           IFNAMSIZ
#define CMD_PHYS_TYPE          char
#define CMD_PORTS_LEN_MAX      PORTS_N
#define CMD_PORTS_LEN_MIN      1
#define CMD_PORTS_TYPE         u16
#define CMD_PPP_SESSION_LEN    1
#define CMD_PPP_SESSION_TYPE   u16
#define CMD_RTT_VAR_LEN        1
#define CMD_RTT_VAR_TYPE       u16
#define CMD_TIMEOUT_LEN        1
#define CMD_TIMEOUT_TYPE       u16
#define CMD_TOS_LEN            1
#define CMD_TOS_TYPE           u8
#define CMD_TTL_LEN            1
#define CMD_TTL_TYPE           u8
#define CMD_TYPE_LEN           1
#define CMD_TYPE_TYPE          u8
#define CMD_VLAN_ID_LEN        1
#define CMD_VLAN_ID_TYPE       u16
#define CMD_WEIGHT_ACKS_LEN    1
#define CMD_WEIGHT_ACKS_TYPE   u8
#define CMD_WEIGHT_NODE_LEN    1
#define CMD_WEIGHT_NODE_TYPE   u8

// CMD SIZES:
// AQUELES QUE USAM PORTA: CONSIDERA O TAMANHO MINIMO DE 1 PORTA, MAS EMBAIXO CHECA TAMBEM O MAXIMO
// SECRET_SET: SIZE:  // LEMBRAR DE VERIFICAR EMBAIXO TAMBEM,
// ports
// password
