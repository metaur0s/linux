#!/bin/bash

set -x
set -e
set -u

# X    haswell
# US-1 cascadelake
# US-2 znver2
# BR   znver2
# PC   znver5
# R7   bdver3

[[ -n ${MYARCH} ]]

case ${MYARCH} in
    znver5)
        sed -r -i -e 's/static_branch_likely\(\&poly1305_use_avx512\)/(1)/g' lib/crypto/x86/poly1305.h
        sed -r -i -e 's/static_branch_likely\(\&chacha_use_avx512vl\)/(1)/g' lib/crypto/x86/chacha.h
        sed -r -i -e 's/static_branch_likely\(\&blake2s_use_avx512\)/(1)/g'  lib/crypto/x86/blake2s.h
        ;;
esac

if grep -q -E -- '-m(cpu|arch|tune)=(generic|core2|i486|i586|i686)' arch/x86/Makefile_32.cpu ; then

    : PATCH

    rm -f -v -- tools/objtool/objtool
    rm -f -v -- tools/objtool/objtool-in.o
    rm -f -v -- tools/objtool/libsubcmd/libsubcmd.a
    rm -f -v -- tools/objtool/libsubcmd/libsubcmd-in.o
    rm -f -v -- tools/objtool/arch/x86/objtool-in.o
    rm -f -v -- arch/x86/boot/setup.elf

    sed -r -i -e 's/cc-option,-mtune=/cc-option,-march=/g' arch/x86/Makefile_32.cpu

    sed -r -i \
        -e "s/call\s*tune,(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|cannon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])/call tune,${MYARCH}/g" \
              -e "s/-mcpu=(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|cannon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])/-march=${MYARCH}/g" \
             -e "s/-march=(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|cannon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])/-march=${MYARCH}/g" \
             -e "s/-mtune=(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|cannon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])/-march=${MYARCH}/g" \
        $(grep -R -E -- '-(cpu|march|mtune)=(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|cannon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])' | awk -F : '{print $1}')

fi

CC_PARAMS=(

)

export   KCFLAGS=" -march=${MYARCH} -mtune=${MYARCH} ${CC_PARAMS[*]}"
export KCPPFLAGS=" -march=${MYARCH} -mtune=${MYARCH} ${CC_PARAMS[*]}"

chmod 0755 GCC.sh

CC=$(pwd)/GCC.sh make -j$((1 + $(grep -c -E '^processor\s' /proc/cpuinfo))) CC=$(pwd)/GCC.sh KCFLAGS="${KCFLAGS}" KCPPFLAGS="${KCPPFLAGS}" > /dev/null

exit $?
