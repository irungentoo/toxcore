#!/bin/sh

CMAKE=$ARCH-w64-mingw32.shared-cmake
CMAKE_EXTRA_FLAGS="-DBOOTSTRAP_DAEMON=OFF -DCOMPILE_AS_CXX=ON"
NPROC=`nproc`
CURDIR=/work

RUN() {
  ./dockcross "$@"
}

ENABLE_WINDOWS_TESTS=false

TESTS() {
  # Download Microsoft DLLs.
  curl http://www.dlldump.com/dllfiles/I/iphlpapi.dll -o _build/iphlpapi.dll
  curl http://www.dlldump.com/dllfiles/W/ws2_32.dll -o _build/ws2_32.dll

  # Copy our dependency DLLs.
  ./dockcross sh -c 'cp $WINEDLLPATH/*.dll _build'

  # Run tests in docker.
  if $ENABLE_WINDOWS_TESTS; then
    ./dockcross "$@" || {
      cat _build/Testing/Temporary/LastTest.log
      false
    }
  fi
}
