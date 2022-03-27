FROM scratch

# Roughly in order of change frequency.
COPY third_party/ /src/third_party/
COPY .github/scripts/flags*.sh /src/.github/scripts/
COPY other/proxy/ /src/other/proxy/
COPY cmake/ /src/cmake/
COPY other/bootstrap_daemon/ /src/other/bootstrap_daemon/
COPY other/pkgconfig/ /src/other/pkgconfig/
COPY other/rpm/ /src/other/rpm/
COPY other/*.[ch] /src/other/
COPY CMakeLists.txt so.version /src/
COPY toxencryptsave/ /src/toxencryptsave/
COPY testing/ /src/testing/
COPY toxav/ /src/toxav/
COPY toxcore/ /src/toxcore/
COPY auto_tests/ /src/auto_tests/
