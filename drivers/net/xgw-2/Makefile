
CFLAGS_xgw.o += -Wfatal-errors
CFLAGS_xgw.o += -Werror
CFLAGS_xgw.o += -Wall
CFLAGS_xgw.o += -Wextra
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

ifneq ($(CONFIG_XGW_3DNOW),)
CFLAGS_xgw.o += -m3dnow
endif

ifneq ($(CONFIG_XGW_MMX),)
CFLAGS_xgw.o += -mmmx
endif

ifneq ($(CONFIG_XGW_SSE),)
CFLAGS_xgw.o += -msse
endif

ifneq ($(CONFIG_XGW_SSE2),)
CFLAGS_xgw.o += -msse2
endif

ifneq ($(CONFIG_XGW_SSE3),)
CFLAGS_xgw.o += -msse3
endif

ifneq ($(CONFIG_XGW_SSSE3),)
CFLAGS_xgw.o += -mssse3
endif

ifneq ($(CONFIG_XGW_SSE4),)
CFLAGS_xgw.o += -msse4
endif

ifneq ($(CONFIG_XGW_SSE4A),)
CFLAGS_xgw.o += -msse4a
endif

ifneq ($(CONFIG_XGW_SSE4_1),)
CFLAGS_xgw.o += -msse4.1
endif

ifneq ($(CONFIG_XGW_SSE4_2),)
CFLAGS_xgw.o += -msse4.2
endif

ifneq ($(CONFIG_XGW_AVX),)
CFLAGS_xgw.o += -mavx
endif

ifneq ($(CONFIG_XGW_AVX2),)
CFLAGS_xgw.o += -mavx2
endif

ifneq ($(CONFIG_XGW_AVX512F),)
CFLAGS_xgw.o += -mavx512f
endif

ifneq ($(CONFIG_XGW_ABM),)
CFLAGS_xgw.o += -mabm
endif

ifneq ($(CONFIG_XGW_TBM),)
CFLAGS_xgw.o += -mtbm
endif

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

ifneq ($(CONFIG_XGW_FXSR),)
CFLAGS_xgw.o += -mfxsr
endif

# -moutline-atomics
# -mno-outline-atomics

obj-$(CONFIG_XGW) += xgw.o
