#!/bin/bash

CPPFLAGS="-DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE"
CPPFLAGS+=("-DCMP_NO_FLOAT=1")
CPPFLAGS+=("-isystem" "/usr/include/opus")
CPPFLAGS+=("-Iauto_tests")
CPPFLAGS+=("-Iauto_tests/scenarios")
CPPFLAGS+=("-Iauto_tests/scenarios/framework")
CPPFLAGS+=("-Iother")
CPPFLAGS+=("-Iother/bootstrap_daemon/src")
CPPFLAGS+=("-Iother/fun")
CPPFLAGS+=("-Itesting")
CPPFLAGS+=("-Itesting/fuzzing")
CPPFLAGS+=("-Itesting/support")
CPPFLAGS+=("-Itesting/support/doubles")
CPPFLAGS+=("-Itesting/support/public")
CPPFLAGS+=("-Itoxcore")
CPPFLAGS+=("-Itoxcore/events")
CPPFLAGS+=("-Itoxav")
CPPFLAGS+=("-Itoxencryptsave")
CPPFLAGS+=("-Ithird_party/cmp")

LDFLAGS=("-lopus" "-lsodium" "-lvpx" "-lpthread" "-lconfig" "-lgmock" "-lgtest" "-lbenchmark")
LDFLAGS+=("-fuse-ld=gold")
LDFLAGS+=("-Wl,--detect-odr-violations")
LDFLAGS+=("-Wl,--warn-common")
LDFLAGS+=("-Wl,--warn-execstack")
LDFLAGS+=("-Wl,-z,noexecstack")
LDFLAGS+=("-Wl,-z,now")

put() {
  if [ "$SKIP_LINES" = "" ]; then
    echo "#line 1 \"$1\"" >>amalgamation.cc
  fi
  grep -v '^BENCHMARK_MAIN' "$1" >>amalgamation.cc
}

putmain() {
  NS=$(echo "${1//[^a-zA-Z0-9_]/_}" | sed -e 's/^__*//')
  echo "namespace $NS {" >>amalgamation.cc
  if [ "$SKIP_LINES" = "" ]; then
    echo "#line 1 \"$1\"" >>amalgamation.cc
  fi
  sed -e 's/^int main(/static &/' "$1" >>amalgamation.cc
  echo "} //  namespace $NS" >>amalgamation.cc
}

callmain() {
  NS=$(echo "${1//[^a-zA-Z0-9_]/_}" | sed -e 's/^__*//')
  echo "  call($NS::main, argc, argv);" >>amalgamation.cc
}

: >amalgamation.cc

# Include all C and C++ code
FIND_QUERY="find . '-(' -name '*.c' -or -name '*.cc' '-)'"
HEADER_QUERY="find . '-(' -name '*.h' -or -name '*.hh' '-)'"

COMMON_EXCLUDES=""
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -wholename './_build/*'"
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -wholename './other/docker/*'"
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -wholename './super_donators/*'"
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -wholename './testing/fuzzing/*'"
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -wholename './third_party/cmp/examples/*'"
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -wholename './third_party/cmp/test/*'"

# File name excludes
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -name amalgamation.cc"
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -name av_test.c"
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -name cracker.c"
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -name version_test.c"
COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -name '*_fuzz_test.cc'"

if [ "$SKIP_BENCHMARK" == 1 ]; then
  COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -name '*_bench.cc'"
fi

if [ "$SKIP_GTEST" == 1 ]; then
  COMMON_EXCLUDES="$COMMON_EXCLUDES -and -not -name '*_test.cc'"
fi

FIND_QUERY="$FIND_QUERY $COMMON_EXCLUDES"
HEADER_QUERY="$HEADER_QUERY $COMMON_EXCLUDES"

readarray -t FILES <<<"$(eval "$FIND_QUERY")"
readarray -t HEADERS <<<"$(eval "$HEADER_QUERY")"

INCLUDES=$(for i in "${FILES[@]}" "${HEADERS[@]}"; do
  grep -o '#include <[^>]*>' "$i" |
    grep -E -v '<win|<ws|<iphlp|<libc|<mach/|<crypto_|<randombytes|<u.h>|<sys/filio|<stropts.h>|<linux'
done | sort -u)

echo "$INCLUDES" | grep "<memory>" >>amalgamation.cc
echo "$INCLUDES" | grep -v "<memory>" >>amalgamation.cc

put auto_tests/check_compat.h

echo 'namespace {' >>amalgamation.cc
for i in "${FILES[@]}"; do
  if ! grep -q '^int main(' "$i"; then
    put "$i"
  fi
done

for i in "${FILES[@]}"; do
  if grep -q '^int main(' "$i"; then
    putmain "$i"
  fi
done

echo "static void call(int m(), int argc, char **argv) { m(); }" >>amalgamation.cc
echo "static void call(int m(int, char **), int argc, char **argv) { m(argc, argv); }" >>amalgamation.cc
echo "static void call(int m(int, const char *const *), int argc, char **argv) { m(argc, argv); }" >>amalgamation.cc
echo '}  // namespace' >>amalgamation.cc

echo "int main(int argc, char **argv) {" >>amalgamation.cc
for i in "${FILES[@]}"; do
  if grep -q '^int main(' "$i"; then
    callmain "$i"
  fi
done
echo "  return 0;" >>amalgamation.cc
echo "}" >>amalgamation.cc
