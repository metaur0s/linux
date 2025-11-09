
enum ENCAP_TYPE {
    ENCAP_TYPE_RAW,
    ENCAP_TYPE_ETH,
    ENCAP_TYPE_ETH_VLAN,
    ENCAP_TYPE_ETH_VLAN_PPP,
    ENCAP_TYPE_ETH_PPP,
};

#define ENCAP_SIZE 32

#define ENCAP_SIZE_ETH          (14)
#define ENCAP_SIZE_ETH_VLAN     (14 + 4)
#define ENCAP_SIZE_ETH_VLAN_PPP (14 + 4 + 8)
#define ENCAP_SIZE_ETH_PPP      (14 + 8)
#define ENCAP_SIZE_RAW          (0)

#define ENCAP_OFFSET_ETH          (ENCAP_SIZE - ENCAP_SIZE_ETH)
#define ENCAP_OFFSET_ETH_VLAN     (ENCAP_SIZE - ENCAP_SIZE_ETH_VLAN)
#define ENCAP_OFFSET_ETH_VLAN_PPP (ENCAP_SIZE - ENCAP_SIZE_ETH_VLAN_PPP)
#define ENCAP_OFFSET_ETH_PPP      (ENCAP_SIZE - ENCAP_SIZE_ETH_PPP)
#define ENCAP_OFFSET_RAW          (ENCAP_SIZE - ENCAP_SIZE_RAW)

// 32 ENCAPSULEMENT
union encap_s { u16 w16 [ENCAP_SIZE/sizeof(u16)];
    struct encap_eth_s {
        u16 _ [ENCAP_OFFSET_ETH/sizeof(u16)];
    // 14 - ETHERNET
        u16 eDst [3];
        u16 eSrc [3];
        u16 eProto;
    } eth;
    struct encap_eth_vlan_s {
        u16 _ [ENCAP_OFFSET_ETH_VLAN/sizeof(u16)];
    // 14 - ETHERNET
        u16 eDst [3];
        u16 eSrc [3];
        u16 eProto;
    // 4 - VLAN
        u16 vID;
        u16 vProto;
    } eth_vlan;
    struct encap_eth_vlan_ppp_s {
        u16 _ [ENCAP_OFFSET_ETH_VLAN_PPP/sizeof(u16)];
    // 14 - ETHERNET
        u16 eDst [3];
        u16 eSrc [3];
        u16 eProto;
    // 4 - VLAN
        u16 vID;
        u16 vProto;
    // 8 - PPP
        u16 pCode;
        u16 pSession;
        u16 pSize;
        u16 pProto;
    } eth_vlan_ppp;
    struct encap_eth_ppp_s {
        u16 _ [ENCAP_OFFSET_ETH_PPP/sizeof(u16)];
    // 14 - ETHERNET
        u16 eDst [3];
        u16 eSrc [3];
        u16 eProto;
    // 8 - PPP
        u16 pCode;
        u16 pSession;
        u16 pSize;
        u16 pProto;
    } eth_ppp;
};

BUILD_ASSERT(sizeof(encap_eth_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_s)     == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ppp_s) == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ppp_s)      == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_s)              == ENCAP_SIZE);

//
#define PKT_SIZE 64

struct pkt_s {
// 32 - ENCAP
    encap_s encap;
// 20 - IPV4
    u8  iVersion;
    u8  iTOS;
    u16 iSize;
    u16 iID;
    u16 iFrag;
    u8  iTTL;
    u8  iProto;
    u16 iCksum;
    u16 iSrc [2];
    u16 iDst [2];
// 8 - UDP
    u16 uSrc;
    u16 uDst;
    u16 uSize;
    u16 uChk;
// 4 - WIREGUARD
    u8 wType;
    u8 wReserved [3]; 
};

BUILD_ASSERT(sizeof(pkt_s) == PKT_SIZE);

