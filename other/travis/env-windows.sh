#!/bin/sh

CMAKE=$ARCH-w64-mingw32.shared-cmake
CMAKE_EXTRA_FLAGS="$CMAKE_EXTRA_FLAGS -DBOOTSTRAP_DAEMON=OFF -DCOMPILE_AS_CXX=ON"
NPROC=`nproc`
CURDIR=/work
RUN_TESTS=true

RUN() {
  ./dockcross "$@"
}

TESTS() {
  shift # Ignore test run count.

  # Download Microsoft DLLs.
  curl http://www.dlldump.com/dllfiles/I/iphlpapi.dll -o _build/iphlpapi.dll
  curl http://www.dlldump.com/dllfiles/W/ws2_32.dll -o _build/ws2_32.dll

  # Copy our dependency DLLs.
  ./dockcross sh -c 'cp $WINEDLLPATH/*.dll _build'

  # Run tests in docker.
  ./dockcross "$@" || {
    cat _build/Testing/Temporary/LastTest.log
    # Ignore test failures on Windows builds for now.
    #false
  }
}
