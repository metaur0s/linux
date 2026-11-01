#!/usr/bin/python

# dd status=none if=/dev/random bs=128 count=1 | base64 --wrap=0 ; echo

import sys
import os
import time
import base64
import binascii
import ipaddress

NODE_NAME_SIZE = 32
PATH_NAME_SIZE = 24

PORTS_N = 65536

IFNAMSIZ = 16

ETH_ALEN = 6

ETH_P_8021Q  = 0x8100
ETH_P_8021AD = 0x88A8

###

_MTU_MIN =   128
_MTU_MAX = 16384

_TTL_MIN =   1
_TTL_MAX = 255

_CONNS_MIN =       1
_CONNS_MAX = 4194304 # 4MB

TOS_MAX = 0xFF

NODES_N = 65536
PATHS_N = 16
PATH_PORTS_N = 4
NODE_NAME_SIZE = 32
PATH_WEIGHT_MAX = 31

PATH_TIMEOUT_MIN =     1
PATH_TIMEOUT_MAX = 65535

CMDS_N = 87
CMD_ERRS_N = 76

# ALL UDP PORTS
UDP_PORTS_N = 65536

(
    CMD_PORT_ON,
    CMD_PORT_OFF,
    CMD_PORT_GET,

    CMD_PORTS_LIST,
    CMD_PORTS_CLEAR,

    CMD_PHYS_ATTACH,
    CMD_PHYS_DETACH,

    CMD_PHYS_LIST,

    CMD_SELF_SET,
    CMD_SELF_GET,

    CMD_GWS_INSERT,
    CMD_GWS_REMOVE,
    CMD_GWS_LIST,
    CMD_GWS_CLEAR,

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

    CMD_PATH_NEW,
    CMD_PATH_DEL,

    CMD_PATH_SET_NAME,
    CMD_PATH_SET_WEIGHT_NODE,
    CMD_PATH_SET_WEIGHT_ACKS,
    CMD_PATH_SET_CLIENT,
    CMD_PATH_SET_SERVER,
    CMD_PATH_SET_TIMEOUT,
    CMD_PATH_SET_RTT_VAR,
    CMD_PATH_SET_DHCP,
    CMD_PATH_SET_PHYS,
    CMD_PATH_SET_TYPE,
    CMD_PATH_SET_ETH_SRC,
    CMD_PATH_SET_ETH_DST,
    CMD_PATH_SET_VLAN_PROTO,
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

    CMD_PATH_SET_IP_TOS,
    CMD_PATH_SET_IP_TTL,

    CMD_PATH_CLR_NAME,
    CMD_PATH_CLR_WEIGHT_NODE,
    CMD_PATH_CLR_WEIGHT_ACKS,
    CMD_PATH_CLR_DHCP,
    CMD_PATH_CLR_PHYS,
    CMD_PATH_CLR_TYPE,
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

    CMD_STATS,

    CMD_NMAP,
) = range(CMDS_N)

(
    CMD_ERR_ALLOC_CMD,
    CMD_ERR_ALLOC_CONNS,
    CMD_ERR_ALLOC_NODE,
    CMD_ERR_INVALID_CONNS_N,
    CMD_ERR_INVALID_MTU,
    CMD_ERR_INVALID_NID,
    CMD_ERR_INVALID_PID,
    CMD_ERR_INVALID_DID,
    CMD_ERR_INVALID_NODE_NAME,
    CMD_ERR_INVALID_PATH_NAME,
    CMD_ERR_INVALID_PHYS,
    CMD_ERR_INVALID_DHCP_IP,
    CMD_ERR_INVALID_PORTS_N,
    CMD_ERR_INVALID_PASSWORD_LEN,
    CMD_ERR_INVALID_TYPE,
    CMD_ERR_INVALID_TOS,
    CMD_ERR_INVALID_TTL,
    CMD_ERR_INVALID_VPROTO,
    CMD_ERR_INVALID_VID,
    CMD_ERR_INVALID_SESSION,
    CMD_ERR_INVALID_WEIGHT,
    CMD_ERR_INVALID_TIMEOUT,
    CMD_ERR_INVALID_RTT,
    CMD_ERR_INVALID_RTT_VAR,
    CMD_ERR_PATH_USE_DHCP_NOT_IP,
    CMD_ERR_PATH_USE_DHCP_NOT_IP_4,
    CMD_ERR_PATH_USE_DHCP_NOT_IP_6,
    CMD_ERR_NODE_EXIST,
    CMD_ERR_NODE_DONT_EXIST,
    CMD_ERR_NODE_IS_OFF,
    CMD_ERR_NODE_IS_ON,
    CMD_ERR_NODE_IS_SELF,
    CMD_ERR_NODE_IS_STOPPING,
    CMD_ERR_NODE_NOT_CONFIGURED,
    CMD_ERR_PATH_EXIST,
    CMD_ERR_PATH_DONT_EXIST,
    CMD_ERR_PATH_IS_OFF,
    CMD_ERR_PATH_IS_ON,
    CMD_ERR_PATH_IS_STOPPING,
    CMD_ERR_PATH_NEED_NAME,
    CMD_ERR_PATH_NEED_CLT_SRV,
    CMD_ERR_PATH_NEED_TIMEOUT,
    CMD_ERR_PATH_NEED_LATENCY_MIN,
    CMD_ERR_PATH_NEED_LATENCY_MAX,
    CMD_ERR_PATH_NEED_RTT_VAR,
    CMD_ERR_PATH_NEED_PHYS,
    CMD_ERR_PATH_NEED_TOS,
    CMD_ERR_PATH_NEED_TTL,
    CMD_ERR_PATH_NEED_MAC_SRC,
    CMD_ERR_PATH_NEED_MAC_DST,
    CMD_ERR_PATH_NEED_ADDR_SRC,
    CMD_ERR_PATH_NEED_ADDR_DST,
    CMD_ERR_PATH_NEED_PORT_SRC,
    CMD_ERR_PATH_NEED_PORT_DST,
    CMD_ERR_PATH_NEED_VLAN_PROTO,
    CMD_ERR_PATH_NEED_VLAN_ID,
    CMD_ERR_PATH_NEED_PPP_SESSION,
    CMD_ERR_PATH_NOT_SERVER,
    CMD_ERR_PATH_NOT_ETH,
    CMD_ERR_PATH_NOT_VLAN,
    CMD_ERR_PATH_NOT_PPP,
    CMD_ERR_PATH_NOT_IP,
    CMD_ERR_PATH_NOT_IP4,
    CMD_ERR_PATH_NOT_IP6,
    CMD_ERR_PATH_NOT_UDP,
    CMD_ERR_PATH_NOT_TCP,
    CMD_ERR_PHYS_IS_BAD,
    CMD_ERR_PHYS_IS_XGW,
    CMD_ERR_PHYS_NOT_FOUND,
    CMD_ERR_PHYS_NOT_HOOKED,
    CMD_ERR_GWS_FULL,
    CMD_ERR_GWS_NID_NOT_FOUND,
    CMD_ERR_GWS_NID_ALREADY,
    CMD_ERR_INVALID_CMD_CODE,
    CMD_ERR_INVALID_CMD_SIZE,
    CMD_ERR_COPY_CMD,
) = range(CMD_ERRS_N)

PASSWORD_SIZE_MAX = 65536

CMD_SIZE_MIN = 1
CMD_SIZE_MAX = 8 + PASSWORD_SIZE_MAX

#############

CMD_CODES = (
    'PORT_ON',
    'PORT_OFF',
    'PORT_GET',

    'PORTS_LIST',
    'PORTS_CLEAR',

    'PHYS_ATTACH',
    'PHYS_DETACH',

    'PHYS_LIST',

    'SELF_SET',
    'SELF_GET',

    'GWS_INSERT',
    'GWS_REMOVE',
    'GWS_LIST',
    'GWS_CLEAR',

    'NODE_NEW',
    'NODE_DEL',

    'NODE_SET_NAME',
    'NODE_SET_MTU',
    'NODE_SET_CONNS_N',
    'NODE_SET_SECRET',

    'NODE_DEV_CREATE',
    'NODE_DEV_DEL',

    'NODE_CLR_NAME',
    'NODE_CLR_SECRET',

    'NODE_ON',
    'NODE_OFF',

    'NODE_STATUS',
    'NODE_STATS',

    'PATH_NEW',
    'PATH_DEL',

    'PATH_SET_NAME',
    'PATH_SET_WEIGHT_NODE',
    'PATH_SET_WEIGHT_ACKS',
    'PATH_SET_CLIENT',
    'PATH_SET_SERVER',
    'PATH_SET_TIMEOUT',
    'PATH_SET_RTT_VAR',
    'PATH_SET_DHCP',
    'PATH_SET_PHYS',
    'PATH_SET_TYPE',
    'PATH_SET_ETH_SRC',
    'PATH_SET_ETH_DST',
    'PATH_SET_VLAN_PROTO',
    'PATH_SET_VLAN_ID',
    'PATH_SET_IP4_TOS',
    'PATH_SET_IP6_TOS',
    'PATH_SET_IP4_TTL',
    'PATH_SET_IP6_TTL',
    'PATH_SET_IP4_SRC',
    'PATH_SET_IP4_DST',
    'PATH_SET_IP6_SRC',
    'PATH_SET_IP6_DST',
    'PATH_SET_UDP_SRC',
    'PATH_SET_TCP_SRC',
    'PATH_SET_UDP_DST',
    'PATH_SET_TCP_DST',

    'PATH_SET_PPP_SESSION',

    'PATH_SET_IP_TOS',
    'PATH_SET_IP_TTL',

    'PATH_CLR_NAME',
    'PATH_CLR_WEIGHT_NODE',
    'PATH_CLR_WEIGHT_ACKS',
    'PATH_CLR_DHCP',
    'PATH_CLR_PHYS',
    'PATH_CLR_TYPE',
    'PATH_CLR_ETH_SRC',
    'PATH_CLR_ETH_DST',
    'PATH_CLR_VLAN_PROTO',
    'PATH_CLR_VLAN_ID',
    'PATH_CLR_IP4_TOS',
    'PATH_CLR_IP6_TOS',
    'PATH_CLR_IP4_TTL',
    'PATH_CLR_IP6_TTL',
    'PATH_CLR_IP4_SRC',
    'PATH_CLR_IP4_DST',
    'PATH_CLR_IP6_SRC',
    'PATH_CLR_IP6_DST',
    'PATH_CLR_UDP_SRC',
    'PATH_CLR_TCP_SRC',
    'PATH_CLR_UDP_DST',
    'PATH_CLR_TCP_DST',

    'PATH_ON',
    'PATH_OFF',

    'PATH_STATUS',
    'PATH_STATS',

    'STATS',

    'NMAP',
)

CMD_ERRS = (
    'CMD_ERR_ALLOC_CMD',
    'CMD_ERR_ALLOC_CONNS',
    'CMD_ERR_ALLOC_NODE',
    'CMD_ERR_INVALID_CONNS_N',
    'CMD_ERR_INVALID_MTU',
    'CMD_ERR_INVALID_NID',
    'CMD_ERR_INVALID_PID',
    'CMD_ERR_INVALID_DID',
    'CMD_ERR_INVALID_NODE_NAME',
    'CMD_ERR_INVALID_PATH_NAME',
    'CMD_ERR_INVALID_PHYS',
    'CMD_ERR_INVALID_DHCP_IP',
    'CMD_ERR_INVALID_PORTS_N',
    'CMD_ERR_INVALID_PASSWORD_LEN',
    'CMD_ERR_INVALID_TYPE',
    'CMD_ERR_INVALID_TOS',
    'CMD_ERR_INVALID_TTL',
    'CMD_ERR_INVALID_VPROTO',
    'CMD_ERR_INVALID_VID',
    'CMD_ERR_INVALID_SESSION',
    'CMD_ERR_INVALID_WEIGHT',
    'CMD_ERR_INVALID_TIMEOUT',
    'CMD_ERR_INVALID_RTT',
    'CMD_ERR_INVALID_RTT_VAR',
    'CMD_ERR_PATH_USE_DHCP_NOT_IP',
    'CMD_ERR_PATH_USE_DHCP_NOT_IP_4',
    'CMD_ERR_PATH_USE_DHCP_NOT_IP_6',
    'CMD_ERR_NODE_EXIST',
    'CMD_ERR_NODE_DONT_EXIST',
    'CMD_ERR_NODE_IS_OFF',
    'CMD_ERR_NODE_IS_ON',
    'CMD_ERR_NODE_IS_SELF',
    'CMD_ERR_NODE_IS_STOPPING',
    'CMD_ERR_NODE_NOT_CONFIGURED',
    'CMD_ERR_PATH_EXIST',
    'CMD_ERR_PATH_DONT_EXIST',
    'CMD_ERR_PATH_IS_OFF',
    'CMD_ERR_PATH_IS_ON',
    'CMD_ERR_PATH_IS_STOPPING',
    'CMD_ERR_PATH_NEED_NAME',
    'CMD_ERR_PATH_NEED_CLT_SRV',
    'CMD_ERR_PATH_NEED_TIMEOUT',
    'CMD_ERR_PATH_NEED_LATENCY_MIN',
    'CMD_ERR_PATH_NEED_LATENCY_MAX',
    'CMD_ERR_PATH_NEED_RTT_VAR',
    'CMD_ERR_PATH_NEED_PHYS',
    'CMD_ERR_PATH_NEED_TOS',
    'CMD_ERR_PATH_NEED_TTL',
    'CMD_ERR_PATH_NEED_MAC_SRC',
    'CMD_ERR_PATH_NEED_MAC_DST',
    'CMD_ERR_PATH_NEED_ADDR_SRC',
    'CMD_ERR_PATH_NEED_ADDR_DST',
    'CMD_ERR_PATH_NEED_PORT_SRC',
    'CMD_ERR_PATH_NEED_PORT_DST',
    'CMD_ERR_PATH_NEED_VLAN_PROTO',
    'CMD_ERR_PATH_NEED_VLAN_ID',
    'CMD_ERR_PATH_NEED_PPP_SESSION',
    'CMD_ERR_PATH_NOT_SERVER',
    'CMD_ERR_PATH_NOT_ETH',
    'CMD_ERR_PATH_NOT_VLAN',
    'CMD_ERR_PATH_NOT_PPP',
    'CMD_ERR_PATH_NOT_IP',
    'CMD_ERR_PATH_NOT_IP4',
    'CMD_ERR_PATH_NOT_IP6',
    'CMD_ERR_PATH_NOT_UDP',
    'CMD_ERR_PATH_NOT_TCP',
    'CMD_ERR_PHYS_IS_BAD',
    'CMD_ERR_PHYS_IS_XGW',
    'CMD_ERR_PHYS_NOT_FOUND',
    'CMD_ERR_PHYS_NOT_HOOKED',
    'CMD_ERR_GWS_FULL',
    'CMD_ERR_GWS_NID_NOT_FOUND',
    'CMD_ERR_GWS_NID_ALREADY',
    'CMD_ERR_INVALID_CMD_CODE',
    'CMD_ERR_INVALID_CMD_SIZE',
    'CMD_ERR_COPY_CMD',
    'OK'
)

assert len(CMD_CODES) ==  CMDS_N
assert len(CMD_ERRS)  == (CMD_ERRS_N + 1)

__ETH  = (1 << 0)
__VLAN = (1 << 1)
__IP4  = (1 << 2)
__IP6  = (1 << 3)
__TCP  = (1 << 4)
__UDP  = (1 << 5)
__PPP  = (1 << 6)

typesNames = {
    'raw'              : 0,
    'ip4'              : __IP4,
    'ip4-udp'          : __IP4  | __UDP,
    'ip4-tcp'          : __IP4  | __TCP,
    'ip6'              : __IP6,
    'ip6-udp'          : __IP6  | __UDP,
    'ip6-tcp'          : __IP6  | __TCP,
    'eth'              : __ETH,
    'eth-ip4'          : __ETH  | __IP4,
    'eth-ip4-udp'      : __ETH  | __IP4   | __UDP,
    'eth-ip4-tcp'      : __ETH  | __IP4   | __TCP,
    'eth-ip6'          : __ETH  | __IP6,
    'eth-ip6-udp'      : __ETH  | __IP6   | __UDP,
    'eth-ip6-tcp'      : __ETH  | __IP6   | __TCP,
    'eth-vlan'         : __ETH  | __VLAN,
    'eth-vlan-ip4'     : __ETH  | __VLAN  | __IP4,
    'eth-vlan-ip4-udp' : __ETH  | __VLAN  | __IP4  | __UDP,
    'eth-vlan-ip4-tcp' : __ETH  | __VLAN  | __IP4  | __TCP,
    'eth-vlan-ip6'     : __ETH  | __VLAN  | __IP6,
    'eth-vlan-ip6-udp' : __ETH  | __VLAN  | __IP6  | __UDP,
    'eth-vlan-ip6-tcp' : __ETH  | __VLAN  | __IP6  | __TCP,
    'eth-vlan-ppp'     : __ETH  | __VLAN | __PPP,
    'eth-vlan-ppp-ip4' : __ETH  | __VLAN | __PPP  | __IP4,
    'eth-vlan-ppp-ip6' : __ETH  | __VLAN | __PPP  | __IP6,
    'eth-ppp'          : __ETH  | __PPP,
    'eth-ppp-ip4'      : __ETH  | __PPP  | __IP4,
    'eth-ppp-ip6'      : __ETH  | __PPP  | __IP6,
}

#############

# !!!
ENDIANESS = 'little'

def U64 (v):
    assert 0 <= v <= ((1 << 64) - 1)
    return v.to_bytes(length=8, signed=False, byteorder=ENDIANESS)

def U32 (v):
    assert 0 <= v <= ((1 << 32) - 1)
    return v.to_bytes(length=4, signed=False, byteorder=ENDIANESS)

def U16 (v):
    assert 0 <= v <= ((1 << 16) - 1)
    return v.to_bytes(length=2, signed=False, byteorder=ENDIANESS)

def U8 (v):
    assert 0 <= v <= ((1 << 8) - 1)
    return v.to_bytes(length=1, signed=False, byteorder=ENDIANESS)

def STR (s, L):
    s = s.encode()
    s += (b'\x00' * (L - len(s)))
    assert len(s) == L
    return s

def PORTS (ports):
    ports = [int(p) for p in ports.split(',')]
    assert 1 <= len(ports) < PORTS_N
    assert all((0 <= p <= 0xFFFF) for p in ports)
    return b''.join(p.to_bytes(length=2, signed=False, byteorder=ENDIANESS) for p in ports)

def PHYS (phys):
    assert 1 <= len(phys) < IFNAMSIZ
    return STR(phys, IFNAMSIZ)

def MAC (mac):
    assert len(mac) == len('XX:XX:XX:XX:XX:XX'), mac
    assert mac.count(':') == 'XX:XX:XX:XX:XX:XX'.count(':'), mac
    return b''.join(int(b, 16).to_bytes(length=1, signed=False, byteorder='big') for b in mac.split(':'))

def IP4 (addr):
    assert addr.count('.') == 3, addr
    # if True: # LITTLE ENDIAN
        # return sum((int(x) << (8*(i))) for i, x in enumerate(addr.split('.')))
    # return sum((int(x) << (32 - 8*(i+1))) for i, x in enumerate(addr.split('.')))
    addr = [int(b, 10) for b in addr.split('.')]
    assert len(addr) == 4
    assert all((0 <= b <= 255) for b in addr)
    return b''.join(b.to_bytes(length=1, signed=False, byteorder='big') for b in addr)


def IP6 (addr):
    return ipaddress.IPv6Address(addr).packed

def oswrite (fd, msg):
    try:
        assert os.write(fd, msg) == len(msg)
        return CMD_ERRS_N
    except OSError as e:
        # LEMBRANDO QUE ESTE ERRNO É O VALOR RETORNADO PELA FUNCAO EM C, POSITIVADO
        return (-e.errno) + 200

def COMM (code, *args):

    assert isinstance(code, int) and 0 <= code < CMDS_N

    assert all(isinstance(a, bytes) for a in args)

    cmd = b''.join((U8(code), *args))

    binsizes.append(len(cmd))

    while (e := oswrite(fd, cmd)) in (
        CMD_ERR_NODE_IS_STOPPING,
        CMD_ERR_PATH_IS_STOPPING
    ): time.sleep(0.4)

    print(CMD_CODES[code], '->', CMD_ERRS[e], binascii.hexlify(cmd[:32], sep='|', bytes_per_sep=8).decode())

binsizes = []

xpath = os.getenv('XGW_PATH', '/proc/xgw')

fd = os.open(xpath, os.O_WRONLY | os.O_CREAT, 0o0644)

args = list(sys.argv)
args.pop(0)

port = phys = nid = pid = None

while args:

    name = v = None

    name = args.pop(0)

    match name:
        case 'stats':
            COMM(CMD_STATS)
        case 'self-set':
            v = int(args.pop(0))
            assert 0 <= v < NODES_N
            COMM(CMD_SELF_SET, U16(v))
        case 'self-get':
            COMM(CMD_SELF_GET)
        case 'gws-insert':
            v = int(args.pop(0))
            assert 0 <= v < NODES_N
            COMM(CMD_GWS_INSERT, U16(v))
        case 'gws-remove':
            v = int(args.pop(0))
            assert 0 <= v < NODES_N
            COMM(CMD_GWS_REMOVE, U16(v))
        case 'gws-list':
            COMM(CMD_GWS_LIST)
        case 'sleep':
            v = float(args.pop(0))
            assert 0 <= v <= 24*60*60
            print(f'SLEEPING FOR {v} SECONDS...')
            time.sleep(v)
        case 'port':
            phys = nid = pid = None
            port = PORTS(args.pop(0))
        case 'phys':
            port = nid = pid = None
            phys = PHYS(args.pop(0))
        case 'node':
            port = phys = pid = None
            nid  = int(args.pop(0))
            assert 0 <= nid < NODES_N
            nid = U16(nid)
        case 'path':
            phys = port = None
            assert nid is not None
            pid  = int(args.pop(0))
            assert 0 <= pid < PATHS_N
            pid = U8(pid)
        case 'attach':
            assert port is nid is pid is None
            assert phys
            COMM(CMD_PHYS_ATTACH, phys)
        case 'detach':
            assert port is nid is pid is None
            assert phys
            COMM(CMD_PHYS_DETACH, phys)
        case 'clt':
            COMM(CMD_PATH_SET_CLIENT, nid, pid)
        case 'srv':
            COMM(CMD_PATH_SET_SERVER, nid, pid)
        case 'create':
            if pid is not None:
                COMM(CMD_PATH_NEW, nid, pid)
            elif nid is not None:
                COMM(CMD_NODE_NEW, nid)
            else:
                assert False
        case 'on':
            if port is not None:
                COMM(CMD_PORT_ON, port)
            elif pid is not None:
                COMM(CMD_PATH_ON, nid, pid)
            elif nid is not None:
                COMM(CMD_NODE_ON, nid)
            else:
                assert False
        case 'off':
            if port is not None:
                COMM(CMD_PORT_OFF, port)
            elif pid is not None:
                COMM(CMD_PATH_OFF, nid, pid)
            elif nid is not None:
                COMM(CMD_NODE_OFF, nid)
            else:
                assert False
        case 'del':
            if pid is not None:
                COMM(CMD_PATH_DEL, nid, pid)
                pid = None
            elif nid is not None:
                COMM(CMD_NODE_DEL, nid)
                nid = None
            else:
                assert False
        case 'status':
            if pid is not None:
                COMM(CMD_PATH_STATUS, nid, pid)
            elif nid is not None:
                COMM(CMD_NODE_STATUS, nid)
            else:
                assert False
        case 'dev-del':
            assert nid is not None
            COMM(CMD_NODE_DEV_DEL, nid)
        case 'nmap':
            assert nid is not None
            nid2  = int(args.pop(0))
            assert 0 <= nid2 < NODES_N
            COMM(CMD_NMAP, nid, U16(nid2))
        case _:

            assert '=' in name, name

            name, v = name.split('=', 1)

            match name:
                case 'dev-create':
                    assert nid is not None
                    COMM(CMD_NODE_DEV_CREATE, nid, STR(v, IFNAMSIZ))
                case 'name':
                    if pid is not None:
                        COMM(CMD_PATH_SET_NAME, nid, pid, STR(v, PATH_NAME_SIZE))
                    elif nid is not None:
                        COMM(CMD_NODE_SET_NAME, nid, STR(v, NODE_NAME_SIZE))
                    else:
                        assert False
                case 'mtu':
                    v = int(v)
                    assert _MTU_MIN <= v <= _MTU_MAX
                    COMM(CMD_NODE_SET_MTU, nid, U16(v))
                case 'timeout':
                    v = int(v)
                    assert PATH_TIMEOUT_MIN <= v <= PATH_TIMEOUT_MAX
                    COMM(CMD_PATH_SET_TIMEOUT, nid, pid, U16(v))
                case 'rtt-var':
                    v = int(v)
                    assert 0 <= v <= 1000
                    COMM(CMD_PATH_SET_RTT_VAR, nid, pid, U16(v))
                case 'conns-n':
                    v = int(v)
                    assert _CONNS_MIN <= v <= _CONNS_MAX
                    COMM(CMD_NODE_SET_CONNS_N, nid, U32(v))
                case 'secret-str':
                    v = v.encode()
                    assert 1 <= len(v) <= PASSWORD_SIZE_MAX
                    COMM(CMD_NODE_SET_SECRET, nid, v)
                case 'secret-base64':
                    v = base64.b64decode(v)
                    assert 1 <= len(v) <= PASSWORD_SIZE_MAX
                    COMM(CMD_NODE_SET_SECRET, nid, v)
                case 'secret-hex':
                    v = int(v, 16).to_bytes(length=(len(v)//2 + len(v)%2), byteorder='big', signed=False)
                    assert 1 <= len(v) <= PASSWORD_SIZE_MAX
                    COMM(CMD_NODE_SET_SECRET, nid, v)
                case 'secret-file':
                    v = open(v, 'rb').read(PASSWORD_SIZE_MAX + 1)
                    assert 1 <= len(v) <= PASSWORD_SIZE_MAX
                    COMM(CMD_NODE_SET_SECRET, nid, v)
                case 'weight-acks':
                    v = int(v)
                    assert 0 <= v <= 0xFF
                    COMM(CMD_PATH_SET_WEIGHT_ACKS, nid, pid, U8(v))
                case 'weight-node':
                    v = int(v)
                    assert 0 <= v <= 0xFF
                    COMM(CMD_PATH_SET_WEIGHT_NODE, nid, pid, U8(v))
                case 'vlan-proto':
                    ETH_P_8021AD = 0x88A8
                    ETH_P_8021Q  = 0x8100
                    if v in ('8021q', '8021Q'):
                        v = ETH_P_8021Q
                    elif v in ('8021ad', '8021AD'):
                        v = ETH_P_8021AD
                    else:
                        v = int(v)
                    assert 0 <= v <= 0xFFFF
                    COMM(CMD_PATH_SET_VLAN_PROTO, nid, pid, U16(v))
                case 'vlan-id':
                    v = int(v)
                    assert 0 <= v <= 4095
                    COMM(CMD_PATH_SET_VLAN_ID, nid, pid, U16(v))
                case 'ppp-session':
                    v = int(v)
                    assert 0 <= v <= 0xFFFF
                    COMM(CMD_PATH_SET_PPP_SESSION, nid, pid, U16(v))
                case 'eth-dst':
                    COMM(CMD_PATH_SET_ETH_DST, nid, pid, MAC(v))
                case 'eth-src':
                    COMM(CMD_PATH_SET_ETH_SRC, nid, pid, MAC(v))
                case 'ip4-tos':
                    assert v.startswith('0x')
                    v = int(v[2:], 16)
                    assert 0 <= v <= TOS_MAX
                    COMM(CMD_PATH_SET_IP4_TOS, nid, pid, U8(v))
                case 'ip6-tos':
                    assert v.startswith('0x')
                    v = int(v[2:], 16)
                    assert 0 <= v <= TOS_MAX
                    COMM(CMD_PATH_SET_IP6_TOS, nid, pid, U8(v))
                case 'ip4-ttl':
                    v = int(v)
                    assert _TTL_MIN <= v <= _TTL_MAX
                    COMM(CMD_PATH_SET_IP4_TTL, nid, pid, U8(v))
                case 'ip6-ttl':
                    v = int(v)
                    assert _TTL_MIN <= v <= _TTL_MAX
                    COMM(CMD_PATH_SET_IP6_TTL, nid, pid, U8(v))
                case 'ip4-src':
                    COMM(CMD_PATH_SET_IP4_SRC, nid, pid, IP4(v))
                case 'ip4-dst':
                    COMM(CMD_PATH_SET_IP4_DST, nid, pid, IP4(v))
                case 'ip6-src':
                    COMM(CMD_PATH_SET_IP6_SRC, nid, pid, IP6(v))
                case 'ip6-dst':
                    COMM(CMD_PATH_SET_IP6_DST, nid, pid, IP6(v))
                case 'udp-src':
                    COMM(CMD_PATH_SET_UDP_SRC, nid, pid, PORTS(v))
                case 'udp-dst':
                    COMM(CMD_PATH_SET_UDP_DST, nid, pid, PORTS(v))
                case 'tcp-src':
                    COMM(CMD_PATH_SET_TCP_SRC, nid, pid, PORTS(v))
                case 'tcp-dst':
                    COMM(CMD_PATH_SET_TCP_DST, nid, pid, PORTS(v))
                case 'phys':
                    COMM(CMD_PATH_SET_PHYS, nid, pid, PHYS(v))
                case 'type':
                    COMM(CMD_PATH_SET_TYPE, nid, pid, U8(typesNames[v]))
                case 'ip-tos':
                    assert v.startswith('0x')
                    v = int(v[2:], 16)
                    assert 0 <= v <= TOS_MAX
                    COMM(CMD_PATH_SET_IP_TOS, nid, pid, U8(v))
                case 'ip-ttl':
                    v = int(v)
                    assert _TTL_MIN <= v <= _TTL_MAX
                    COMM(CMD_PATH_SET_IP_TTL, nid, pid, U8(v))
                case _:
                    assert False, (name, v)

if os.getenv('XGW_PATH', ''):
    open(f'{xpath}.sizes', 'w').write(' '.join(map(str, binsizes)))

'''
for S in $(cat /xgw.sizes) ; do
    dd bs=${S} count=1
done < /xgw.bin > /proc/xgw
'''
