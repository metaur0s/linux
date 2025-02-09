//

#define _CONNS_MIN       1
#define _CONNS_MAX 4194304 // 4MB

// VALIDATE CONFIG

#if CONFIG_XGW_CONNS_MIN < _CONNS_MIN \
 || CONFIG_XGW_CONNS_MIN > _CONNS_MAX
#error    "BAD CONNS MIN"
#endif

#if CONFIG_XGW_CONNS_MAX < _CONNS_MIN \
 || CONFIG_XGW_CONNS_MAX > _CONNS_MAX
#error    "BAD CONNS MAX"
#endif

#if CONFIG_XGW_CONNS_MIN \
  > CONFIG_XGW_CONNS_MAX
#error    "BAD CONNS MIN/MAX"
#endif

#ifdef CONFIG_XGW_BEEP

#if CONFIG_XGW_BEEP_BASE < 100
#error    "BAD BEEP BASE"
#endif

#if CONFIG_XGW_BEEP_MAX > 5000
#error    "BAD BEEP MAX"
#endif

#if ((CONFIG_XGW_BEEP_BASE >= CONFIG_XGW_BEEP_MAX) && (CONFIG_XGW_BEEP_BASE - CONFIG_XGW_BEEP_MAX) >  1000) \
 || ((CONFIG_XGW_BEEP_BASE <= CONFIG_XGW_BEEP_MAX) && (CONFIG_XGW_BEEP_BASE - CONFIG_XGW_BEEP_MAX) < -1000)
#error    "BAD BEEP BASE/MAX"
#endif

#endif
