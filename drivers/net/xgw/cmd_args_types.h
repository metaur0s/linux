
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
