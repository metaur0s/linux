#!/bin/bash

set -e
set -u

CC_PARAMS=(
    --param max-pending-list-length=10000
    --param max-gcse-memory=65536
    --param max-modulo-backtrack-attempts=8000
    --param max-stores-to-merge=20000
    --param max-store-chains-to-track=10000
    --param max-stores-to-track=20000
    --param dse-max-object-size=67108864
    --param dse-max-alias-queries-per-store=8000
    --param vect-max-layout-candidates=8000
    --param vect-max-version-for-alignment-checks=8000
    --param max-iterations-to-track=20000
    --param tracer-max-code-growth=200
)

case "$(pwd) ${*}" in

    # THERE'S NO POINT ON OPTIMIZING IF THE BUILD WON'T FINISH IN THIS CENTURY
    *amdgpu*) : ;;
    *drivers/gpu/drm/amd/*) : ;;
    
    *maple*|*net/core/dev*|*realtek*|*net/core/skbuff*|*net/core/fib_rules*|*net/ipv4*|*wireguard*|*crypto/*|*aes-gcm*|*poly1305*|*chacha20*|*curve25519*|*blake2*|*sha256*|*sha512*|*sha1-avx2*) 
        CC_PARAMS=(
            --param max-pending-list-length=32768
            --param max-gcse-memory=865536
            --param max-modulo-backtrack-attempts=32768
            --param max-stores-to-merge=32768
            --param max-store-chains-to-track=32768
            --param max-stores-to-track=88000
            --param dse-max-object-size=867108864
            --param dse-max-alias-queries-per-store=88000
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

exec /usr/bin/gcc "${CC_PARAMS[@]}" "${@}"
