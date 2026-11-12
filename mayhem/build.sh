#!/usr/bin/env bash
#
# mayhem/build.sh: tengine (nginx fork) in-process parser fuzzers, the real binary and a known-answer probe.
# Runs in the commit image as `mayhem` in /mayhem; offline and re-runnable.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

MODULES=(--with-http_v2_module --with-stream --with-pcre --with-mail
         --add-module=modules/mod_common --add-module=modules/mod_config
         --add-module=modules/ngx_multi_upstream_module
         --add-module=modules/mod_dubbo)

# 1) Test build: the project's normal flags. objs-test/nginx is the real server binary that
#    test.sh runs; the kat probe links the same (unsanitized) objects.
./configure --builddir=objs-test --with-cc="$CC" \
    --with-cc-opt="-O1 $COVERAGE_FLAGS" --with-ld-opt="$COVERAGE_FLAGS" "${MODULES[@]}" >/dev/null
make -f objs-test/Makefile -j"$MAYHEM_JOBS" >/dev/null

# nginx's ngx_str3_cmp()/ngx_str4cmp() macros compare bytes with deliberately misaligned uint32 loads on x86
# (NGX_HAVE_NONALIGNED), which UBSan's alignment check reports on any HTTP method token: relaxed here
# (and only here). mod_dubbo's Hessian2 reader forms multi-byte values as ((tag - 60) << 16) + ..., a
# left shift of a negative int that is benign on the targeted compilers and flooded the dubbo target with
# one report per call site (shift-base); relaxed too. ASan and every other UBSan check stay on and halting.
RELAX="-fno-sanitize=alignment,shift-base"

# 2) Fuzz build (linked with $CXX so the UBSan C++ runtime, needed by the vptr check in mod_dubbo, is pulled in): every nginx/tengine object is compiled with sanitizers + SanCov (-fsanitize=fuzzer-no-link,
#    unconditionally, so coverage exists even with an empty SANITIZER_FLAGS) and DWARF 3.
./configure --builddir=objs-fuzz --with-cc="$CC" \
    --with-cc-opt="$SANITIZER_FLAGS $RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1" \
    --with-ld-opt="$SANITIZER_FLAGS" "${MODULES[@]}" >/dev/null
make -f objs-fuzz/Makefile LINK="$CXX" -j"$MAYHEM_JOBS" >/dev/null

# Objects, libraries and include paths come from the generated Makefiles, so module/OS differences follow
# upstream's own configure result. nginx.o holds main(): renamed so libFuzzer's main wins.
objs_and_libs() {
    awk -v d="$1" '$0 ~ "LINK\\) -o " d "/nginx"{f=1; next} f{print} f&&!/\\$/{exit}' "$1/Makefile" \
        | sed -e 's/\\$//' -e "s#$1/src/core/nginx.o##" -e 's/-Wl,-E//' -e 's/-fsanitize=[a-z,]*//g' | tr -s ' \t\n' ' '
}
incs_for() {
    awk '/^ALL_INCS/{f=1} f{print} f&&!/\\$/{exit}' "$1/Makefile" | sed -e 's/^ALL_INCS =//' -e 's/\\$//' | tr -s ' \t\n' ' '
}

rename_main() {
    objcopy --redefine-sym main=ngx_tengine_main "$1/src/core/nginx.o" "$1/nginx_nomain.o"
}

# 3) Known-answer probe (normal flags).
rename_main objs-test
# shellcheck disable=SC2046
$CC -O1 $COVERAGE_FLAGS $(incs_for objs-test) mayhem/kat/kat.c objs-test/nginx_nomain.o \
    $(objs_and_libs objs-test) -lstdc++ -o /mayhem/kat_probe

# 4) Fuzz harnesses, once with libFuzzer and once with the standalone run-once driver.
rename_main objs-fuzz
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o objs-fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o objs-fuzz/standalone_main.o
INCS=$(incs_for objs-fuzz)
LIBS=$(objs_and_libs objs-fuzz)
for h in fuzz_http_request fuzz_http_response fuzz_http_chunked fuzz_core_util fuzz_mail_command fuzz_dubbo_hessian2; do
    # shellcheck disable=SC2086
    $CC $SANITIZER_FLAGS $RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 $INCS -Imayhem/harnesses -c \
        "mayhem/harnesses/$h.c" -o "objs-fuzz/$h.o"
    # shellcheck disable=SC2086
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "objs-fuzz/$h.o" objs-fuzz/lsan_off.o \
        objs-fuzz/nginx_nomain.o $LIBS -o "/mayhem/$h"
    # shellcheck disable=SC2086
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS objs-fuzz/standalone_main.o "objs-fuzz/$h.o" objs-fuzz/lsan_off.o \
        objs-fuzz/nginx_nomain.o $LIBS -o "/mayhem/$h-standalone"
done
