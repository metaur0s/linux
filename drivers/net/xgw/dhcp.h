
#define DHCP_NAME_SIZE 32

#define DHCP_SIZE 128

typedef struct dhcp_s {
// 16
    net_device_s* dev;
    u16 neighProtocol;
    u16 leaseProtocol;
    u8 neighSize;
    u8 netmask; // NETMASK OBTIDO
    u8 status; // DHCP4_* / DHCP6_* / RA_*
    u8 flags; //  BROADCAST ARP? FORCE gw6? force gwMAC?
// 24
    u32 xid; // DHCP
    u16 mtu; // MTU OBTIDO
    u8 myMAC [ETH_ALEN];
    u8 gwMAC [ETH_ALEN];
    u8 srvMAC [ETH_ALEN];
// 24
    skb_s* skb; // SO NO CASO DE SER BROADCAST
    u64 broadcastLast;
    u64 reserved;
// 64
    union {
    // 12
        struct { // IPV4
            u32 ip; // IP (AND NETWORK) GOT
            u32 gw; // IP OF GATEWAY
            u32 srv; // IP OF SERVER
        } v4;
    // 64
        struct { // IPV6
            u16 ip [8]; // IP (AND NETWORK) GOT
            u16 ll [8];
            u16 gw [8]; // IP OF GATEWAY
            u16 srv [8]; // IP OF SERVER
        } v6;
    };
} dhcp_s;

#define DHCP_NOT_HANDLED 0
#define DHCP_HANDLED     1 // E DROP O SKB
