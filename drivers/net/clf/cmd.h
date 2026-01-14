
// COMMANDS
enum CMDS {
    CMD_PATH_ON,
    CMD_PATH_OFF,
    CMD_PATH_PRINT,
    CMD_PATH_PHYS_SET,
    CMD_PATH_PHYS_CLR,
    CMD_PATH_ENCAP_RAW,
    CMD_PATH_ENCAP_ETH,
    CMD_PATH_ENCAP_ETH_VLAN,
    CMD_PATH_ENCAP_ETH_VLAN_PPP,
    CMD_PATH_ENCAP_ETH_VLAN_PPP_SESSION,
    CMD_PATH_ENCAP_ETH_PPP,
    CMD_PATH_ENCAP_ETH_PPP_SESSION,
};

#define CMD_SIZE 64

struct cmd_s {
    u8 code;
    u8 pid;
    char phys [30];
    encap_s encap;
};

BUILD_ASSERT(sizeof(cmd_s) == CMD_SIZE);
