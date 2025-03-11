
CFLAGS_REMOVE_xgw.o += -Wno-unused-label

CFLAGS_xgw.o += -Wfatal-errors
CFLAGS_xgw.o += -Werror
CFLAGS_xgw.o += -Wall
CFLAGS_xgw.o += -Wextra
CFLAGS_xgw.o += -Wunused-label
CFLAGS_xgw.o += -Wsizeof-array-argument
CFLAGS_xgw.o += -Wno-declaration-after-statement
CFLAGS_xgw.o += -Wno-missing-declarations
CFLAGS_xgw.o += -Wno-missing-prototypes
CFLAGS_xgw.o += -Wno-error=sign-compare
CFLAGS_xgw.o += -Wno-error=unused-parameter
CFLAGS_xgw.o += -Wno-error=unused-function
CFLAGS_xgw.o += -Wno-error=unused-label
CFLAGS_xgw.o += -Wno-error=unused-variable
CFLAGS_xgw.o += -Wno-error=date-time
CFLAGS_xgw.o += -Wno-type-limits
CFLAGS_xgw.o += -Wno-unused-parameter
CFLAGS_xgw.o += -Wno-sign-compare
CFLAGS_xgw.o += -Wno-c23-extensions

CFLAGS_xgw.o += -mpopcnt

# TODO: CLANG NAO TEM ABM
#ifneq ($(CONFIG_XGW_ABM),)
#CFLAGS_xgw.o += -mabm
#endif

#ifneq ($(CONFIG_XGW_TBM),)
#CFLAGS_xgw.o += -mtbm
#endif

ifneq ($(CONFIG_XGW_FMA),)
CFLAGS_xgw.o += -mfma
endif

ifneq ($(CONFIG_XGW_FMA4),)
CFLAGS_xgw.o += -mfma4
endif

ifneq ($(CONFIG_XGW_F16C),)
CFLAGS_xgw.o += -mf16c
endif

ifneq ($(CONFIG_XGW_RDRAND),)
CFLAGS_xgw.o += -mrdrnd
endif

ifneq ($(CONFIG_XGW_PCLMUL),)
CFLAGS_xgw.o += -mpclmul
endif

ifneq ($(CONFIG_XGW_BMI),)
CFLAGS_xgw.o += -mbmi
endif

ifneq ($(CONFIG_XGW_BMI2),)
CFLAGS_xgw.o += -mbmi2
endif

# -moutline-atomics
# -mno-outline-atomics

obj-$(CONFIG_XGW) += xgw.o
