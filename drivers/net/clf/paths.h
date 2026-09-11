
#define PATHS_N 16

struct path_s {
    u8 eType;
    u8 eSize;
    u8 eOffset; // ENCAP_OFFSET_*
    u8 nOffset;
    u8 pword;
    u8 mac_len; // SKB MAC LEN
    u16 protocol; // SKB PROTOCOL
    u64 reserved64 [2];
// 8 - DEVICE
    net_device_s* phys;
// 32 - ENCAP
    encap_s encap;
};

BUILD_ASSERT(sizeof(path_s) == 64);
