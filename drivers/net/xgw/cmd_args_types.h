
#define CMD_ARG(a, b, c) a ## b ## c

// CHECK IF THE COMMAND MESSAGE IS COMPLETE
#define CMD_ARG_SIZE(arg) sizeof(CMD_ARG(cmd_arg_, arg, _t))
#define CMD_VALUE(arg) (*(CMD_ARG(cmd_arg_, arg, _t)*)cmd)

#define CMD_CONSUME(_type) { \
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
typedef u16 cmd_arg_eth_proto_t;
typedef u16 cmd_arg_vlan_id_t;
typedef u8  cmd_arg_tos_t;
typedef u8  cmd_arg_ttl_t;
typedef u8  cmd_arg_type_t;
typedef u8  cmd_arg_weight_node_t;
typedef u8  cmd_arg_weight_acks_t;
typedef u16 cmd_arg_timeout_t;
typedef u16 cmd_arg_rtt_t;
typedef u16 cmd_arg_rtt_var_t;
typedef u16 cmd_arg_ppp_session_t;

typedef char cmd_arg_nname_t[NODE_NAME_SIZE];
typedef char cmd_arg_pname_t[PATH_NAME_SIZE];
typedef char cmd_arg_dname_t[DHCP_NAME_SIZE];
typedef char cmd_arg_phys_t[IFNAMSIZ];
typedef u8   cmd_arg_password_t[PASSWORD_SIZE_MAX];
typedef u8   cmd_arg_mac_t[ETH_ALEN];
typedef u16  cmd_arg_path_ports_t[PATH_PORTS_N];
typedef u8   cmd_arg_addr4_t[4];
typedef u16  cmd_arg_addr6_t[8];
typedef u16  cmd_arg_ports_t[PORTS_N];

// CMD SIZES:
// AQUELES QUE USAM PORTA: CONSIDERA O TAMANHO MINIMO DE 1 PORTA, MAS EMBAIXO CHECA TAMBEM O MAXIMO
// SECRET_SET: SIZE:  // LEMBRAR DE VERIFICAR EMBAIXO TAMBEM,
typedef u16 cmd_arg_ports_min_t[1];
typedef u8 cmd_arg_secret_min_t[16];
