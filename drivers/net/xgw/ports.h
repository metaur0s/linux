
// ALL UDP PORTS
#define UDP_PORTS_N 65536

//
#define PORTS_N (UDP_PORTS_N / PORTS_WIDTH)

#define PORTS_WIDTH 32
#define PORTS_SHIFT 5
#define PORTS_MASK 0b11111
#define PORTS_W (ports[port >> PORTS_SHIFT])
#define PORTS_B (1 << (port & PORTS_MASK))

typedef int ports_t;
