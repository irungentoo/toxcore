#!/bin/sh

CPPFLAGS="$CPPFLAGS -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE"
CPPFLAGS="$CPPFLAGS -isystem /usr/include/opus"
CPPFLAGS="$CPPFLAGS -Iauto_tests"
CPPFLAGS="$CPPFLAGS -Iother"
CPPFLAGS="$CPPFLAGS -Iother/bootstrap_daemon/src"
CPPFLAGS="$CPPFLAGS -Iother/fun"
CPPFLAGS="$CPPFLAGS -Itesting"
CPPFLAGS="$CPPFLAGS -Itoxcore"
CPPFLAGS="$CPPFLAGS -Itoxav"
CPPFLAGS="$CPPFLAGS -Itoxencryptsave"

LDFLAGS="$LDFLAGS -lopus -lsodium -lvpx -lpthread -lconfig"

put() {
  if [ "$SKIP_LINES" = "" ]; then
    echo "#line 1 \"$1\"" >> amalgamation.cc
  fi
  cat $1 >> amalgamation.cc
}

putmain() {
  echo "namespace $(echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g') {" >> amalgamation.cc
  if [ "$SKIP_LINES" = "" ]; then
    echo "#line 1 \"$1\"" >> amalgamation.cc
  fi
  sed -e 's/^int main(/static &/' $1 >> amalgamation.cc
  echo "} //  namespace $(echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g')" >> amalgamation.cc
}

callmain() {
  echo "  call($(echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g')::main, argc, argv);" >> amalgamation.cc
}

:> amalgamation.cc

echo "#include <algorithm>" >> amalgamation.cc
echo "#include <cstdio>" >> amalgamation.cc
echo "#include <memory>" >> amalgamation.cc
echo "#include <random>" >> amalgamation.cc

put auto_tests/check_compat.h

FIND_QUERY="find . '-(' -name '*.cc' -or -name '*.c' '-)'"
FIND_QUERY="$FIND_QUERY -and -not -wholename './_build/*'"
FIND_QUERY="$FIND_QUERY -and -not -wholename './super_donators/*'"
FIND_QUERY="$FIND_QUERY -and -not -wholename './toxav/*.cc'"
FIND_QUERY="$FIND_QUERY -and -not -wholename './toxcore/*.cc'"
FIND_QUERY="$FIND_QUERY -and -not -wholename './toxencryptsave/*.cc'"
FIND_QUERY="$FIND_QUERY -and -not -name amalgamation.cc"
FIND_QUERY="$FIND_QUERY -and -not -name av_test.c"
FIND_QUERY="$FIND_QUERY -and -not -name dht_test.c"
FIND_QUERY="$FIND_QUERY -and -not -name version_test.c"

for i in $(eval $FIND_QUERY); do
  if ! grep -q '^int main(' $i; then
    put $i
  fi
done

for i in $(eval $FIND_QUERY); do
  if grep -q '^int main(' $i; then
    putmain $i
  fi
done

echo "static void call(int m(), int argc, char **argv) { m(); }" >> amalgamation.cc
echo "static void call(int m(int, char **), int argc, char **argv) { m(argc, argv); }" >> amalgamation.cc

echo "int main(int argc, char **argv) {" >> amalgamation.cc
for i in $(eval $FIND_QUERY); do
  if grep -q '^int main(' $i; then
    callmain $i
  fi
done
echo "  return 0;" >> amalgamation.cc
echo "}" >> amalgamation.cc
