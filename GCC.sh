#!/bin/bash

set -e
set -u

GCC_MAX_GCE_MEMORY=865536
GCC_DSE_MAX_OBJECT_SIZE=1024
GCC_DSE_MAX_ALIAS_QUERIES_PER_STORE=8000
GCC_MAX_PENDING_LIST_LENGTH=64

CC_PARAMS=(
    --param max-pending-list-length=$((GCC_MAX_PENDING_LIST_LENGTH*1))
    --param max-gcse-memory=$((GCC_MAX_GCE_MEMORY*1))
    --param max-modulo-backtrack-attempts=8000
    --param max-stores-to-merge=20000
    --param max-store-chains-to-track=10000
    --param max-stores-to-track=20000
    --param dse-max-object-size=$((GCC_DSE_MAX_OBJECT_SIZE*1))
    --param dse-max-alias-queries-per-store=$((GCC_DSE_MAX_ALIAS_QUERIES_PER_STORE*1))
    --param vect-max-layout-candidates=8000
    --param vect-max-version-for-alignment-checks=8000
    --param max-iterations-to-track=20000
    --param tracer-max-code-growth=200
)

case "$(pwd) ${*}" in

    # THERE'S NO POINT ON OPTIMIZING IF THE BUILD WON'T FINISH IN THIS CENTURY
    *amdgpu*) : ;;
    *drivers/gpu/drm/amd/*) : ;;

    # crypto
    # lib/crypto
    # lib/zstd
    # drivers/crypto
    # drivers/net/wireguard
    # drivers/net/xgw
    # drivers/net/ethernet/realtek
    # drivers/net/wireless/realtek
    *maple*|*net/core/dev*|*net/core/skbuff*|*net/core/fib_rules*|*net/ipv*|*lib/zstd*|*drivers/net/ethernet/realtek*|*drivers/net/wireless/realtek*|*drivers/net/xgw*|*wireguard*|*crypto/*)
        CC_PARAMS=(
            --param max-pending-list-length=$((GCC_MAX_PENDING_LIST_LENGTH*4))
            --param max-gcse-memory=$((GCC_MAX_GCE_MEMORY*2))
            --param max-modulo-backtrack-attempts=32768
            --param max-stores-to-merge=32768
            --param max-store-chains-to-track=32768
            --param max-stores-to-track=88000
            --param dse-max-object-size=$((GCC_DSE_MAX_OBJECT_SIZE*4))
            --param dse-max-alias-queries-per-store=$((GCC_DSE_MAX_ALIAS_QUERIES_PER_STORE*8))
            --param vect-max-layout-candidates=88000
            --param vect-max-version-for-alignment-checks=32768
            --param max-iterations-to-track=32768
            --param tracer-max-code-growth=10000 # 100x
            --param max-inline-insns-single=65536
            --param inline-unit-growth=8192
            --param ipa-cp-unit-growth=50
            # --param ipcp-unit-growth=50 # The default value is 10 which limits unit growth to 1.1 times the original size.
        )
	;;
    
esac

#
CC_PARAMS+=(-Wno-constant-logical-operand)

exec /x86_64-x-linux-musl/bin/x86_64-x-linux-musl-gcc "${CC_PARAMS[@]}" "${@}"

# find . -type f -iname '*.o' -printf '%s %p\n' | sort -n
