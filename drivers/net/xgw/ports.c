
// TODO: SO APRENDER UM PATH SE TAL PORTA ESTIVER CONFIGURADA NELE
static inline void ports_enable (const uint port) {

    PORTS_W |= PORTS_B;
}

static inline void ports_disable (const uint port) {

    PORTS_W &= ~PORTS_B;
}

static inline ports_t ports_is_enabled (const uint port) {

    return PORTS_W & PORTS_B;
}
