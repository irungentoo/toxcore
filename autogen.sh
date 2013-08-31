#!/bin/sh -e

echo 'Running autoreconf -if...'
(
  rm -rf autom4te.cache
  rm -f aclocal.m4 ltmain.sh
  autoreconf -if ${AC_FLAGS}
)

echo 'Running ./configure...'
(
  ./configure
)
