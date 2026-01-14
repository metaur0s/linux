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
        -e "s/call\s*tune,(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|canon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])/call tune,${MYARCH}/g" \
              -e "s/-mcpu=(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|canon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])/-march=${MYARCH}/g" \
             -e "s/-march=(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|canon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])/-march=${MYARCH}/g" \
             -e "s/-mtune=(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|canon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])/-march=${MYARCH}/g" \
        $(grep -R -E -- '-(cpu|march|mtune)=(x86[_-]64|generic|native|core2|i[456]86|atom|(sky|canon|cascade)lake|athlon|k[678]|(broad|has)well|(bd|zn)ver[1-9])' | awk -F : '{print $1}')

fi

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

export   KCFLAGS=" -march=${MYARCH} -mtune=${MYARCH} ${CC_PARAMS[*]}"
export KCPPFLAGS=" -march=${MYARCH} -mtune=${MYARCH} ${CC_PARAMS[*]}"

make -j$((1 + $(grep -c -E '^processor\s' /proc/cpuinfo))) KCFLAGS="${KCFLAGS}" KCPPFLAGS="${KCPPFLAGS}" > /dev/null

exit $?
