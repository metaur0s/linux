
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
ifeq ($(CONFIG_CC_IS_CLANG),y)
CFLAGS_xgw.o += -Wno-c23-extensions
endif

CFLAGS_xgw.o += -mpopcnt

# -mabm
# -mbmi
# -mbmi2
# -mf16c
# -mfma
# -mfma4
# -mpclmul
# -mtbm

ifneq ($(CONFIG_XGW_RDRAND),)
CFLAGS_xgw.o += -mrdrnd
endif


# -moutline-atomics
# -mno-outline-atomics

obj-$(CONFIG_XGW) += xgw.o
