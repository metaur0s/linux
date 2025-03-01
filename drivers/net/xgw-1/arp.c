
#define ACODE_REQUEST  0x0001080006040001ULL
#define ACODE_REPLY    0x0001080006040002ULL

#define        ARP_HDR_S 56 
typedef struct arp_hdr_s {
// 24 ETHERNET, VLAN
    union {
        struct {
        //  6 ALIGN
            u16 _align[3];
        // 14 ETHERNET
            u8  edst [ETH_ALEN];
            u8  esrc [ETH_ALEN];
            u16 etype;
        //  4 VLAN
            u16 vid;
            u16 vtype;
        } v;
        struct {
            //  2 ALIGN
            u16 _align;
            // 14 ETHERNET
            u8  edst [ETH_ALEN];
            u8  esrc [ETH_ALEN];
            u16 etype;
        };
    };
// 28 ARP
    u64 acode;
    u8  aesrc [ETH_ALEN];
    u8  aisrc [4];
    u8  aedst [ETH_ALEN];
    u8  aidst [4];
} arp_hdr_s;

    // recebeu um pacote ARP request
    req 
    
    memcpy(&resp->edst, &req->esrc, ETH_ALEN);        
    memcpy(&resp->esrc, , ETH_ALEN);            // MEU ETH
            resp->etype = BE16(0x0806);        // ARP
            resp->acode = BE64(ACODE_REPLY);
    memcpy(&resp->aesrc, , ETH_ALEN);            // MEU ETH
    memcpy(&resp->aisrc, , 4);                     // MEU IP
    memcpy(&resp->aedst, &req->aesrc, ETH_ALEN);
    memcpy(&resp->aidst, , 4);
    
    // marca para enviar o arp response

